use alloy_primitives::{B256, map::HashSet};
use anyhow::{anyhow, ensure};
use hashbrown::HashMap;
use ream_consensus_misc::{
    checkpoint::Checkpoint,
    constants::beacon::GENESIS_EPOCH,
    misc::{compute_epoch_at_slot, compute_start_slot_at_epoch},
};

/// Data required to place a block in the tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForkChoiceBlock {
    pub root: B256,
    pub parent_root: B256,
    pub slot: u64,
    /// `current_justified_checkpoint` of the block's post-state.
    pub justified_checkpoint: Checkpoint,
    /// Pulled-up justification of the block
    pub unrealized_justified_checkpoint: Checkpoint,
}

/// Store-level values the viability of a block depends on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ViabilityContext {
    pub justified_checkpoint: Checkpoint,
    pub finalized_checkpoint: Checkpoint,
    pub current_epoch: u64,
}

#[derive(Debug, Clone)]
struct ForkChoiceNode {
    parent: Option<B256>,
    slot: u64,
    children: Vec<B256>,
    justified_checkpoint: Checkpoint,
    unrealized_justified_checkpoint: Checkpoint,
    /// Attesting balance of this block's subtree plus the proposer boost if the boosted block is
    /// in the subtree.
    weight: u64,
    /// Whether the subtree contains a leaf that passes the spec's viability filter.
    viable: bool,
    /// The head reached by following the best viable child at every level, or the node itself if
    /// none of its children is viable.
    best_descendant: B256,
}

#[derive(Debug, Clone, Copy)]
struct AppliedVote {
    root: B256,
    balance: u64,
}

#[derive(Debug)]
pub struct ForkChoiceTree {
    root: B256,
    nodes: HashMap<B256, ForkChoiceNode>,
    context: ViabilityContext,
    /// Effective balance per validator index of the justified checkpoint state; zero for
    /// validators that are inactive or slashed.
    balances: Vec<u64>,
    balances_checkpoint: Option<Checkpoint>,
    proposer_score: u64,
    votes: HashMap<u64, AppliedVote>,
    equivocating: HashSet<u64>,
    boost: Option<(B256, u64)>,
}

impl ForkChoiceTree {
    /// Creates a tree containing only `anchor`, the finalized block.
    pub fn new(anchor: ForkChoiceBlock, context: ViabilityContext) -> Self {
        let mut nodes = HashMap::default();
        nodes.insert(
            anchor.root,
            ForkChoiceNode {
                parent: None,
                slot: anchor.slot,
                children: vec![],
                justified_checkpoint: anchor.justified_checkpoint,
                unrealized_justified_checkpoint: anchor.unrealized_justified_checkpoint,
                weight: 0,
                viable: false,
                best_descendant: anchor.root,
            },
        );
        let mut tree = Self {
            root: anchor.root,
            nodes,
            context,
            balances: vec![],
            balances_checkpoint: None,
            proposer_score: 0,
            votes: HashMap::default(),
            equivocating: HashSet::default(),
            boost: None,
        };
        tree.update_node(anchor.root);
        tree
    }

    /// Root of the tree, i.e. the finalized block.
    pub fn root(&self) -> B256 {
        self.root
    }

    pub fn contains(&self, root: &B256) -> bool {
        self.nodes.contains_key(root)
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    pub fn context(&self) -> &ViabilityContext {
        &self.context
    }

    /// Checkpoint whose state the balances were derived from.
    pub fn balances_checkpoint(&self) -> Option<Checkpoint> {
        self.balances_checkpoint
    }

    pub fn proposer_score(&self) -> u64 {
        self.proposer_score
    }

    pub fn weight(&self, root: &B256) -> Option<u64> {
        self.nodes.get(root).map(|node| node.weight)
    }

    /// The LMD-GHOST head: `nodes[justified_root].best_descendant`.
    ///
    /// When the justified block is not part of the tree no leaf can be viable, and the spec's
    /// `get_head` returns the justified root itself.
    pub fn head(&self) -> B256 {
        let justified_root = self.context.justified_checkpoint.root;
        self.nodes
            .get(&justified_root)
            .map_or(justified_root, |node| node.best_descendant)
    }

    /// Adds a block. Only the new node and its ancestor chain are updated.
    pub fn insert(&mut self, block: ForkChoiceBlock) -> anyhow::Result<()> {
        if self.nodes.contains_key(&block.root) {
            return Ok(());
        }
        let parent = self.nodes.get_mut(&block.parent_root).ok_or_else(|| {
            anyhow!(
                "parent {} of {} is not in the tree",
                block.parent_root,
                block.root
            )
        })?;
        ensure!(
            block.slot > parent.slot,
            "block {} slot {} is not above parent slot {}",
            block.root,
            block.slot,
            parent.slot
        );
        parent.children.push(block.root);
        self.nodes.insert(
            block.root,
            ForkChoiceNode {
                parent: Some(block.parent_root),
                slot: block.slot,
                children: vec![],
                justified_checkpoint: block.justified_checkpoint,
                unrealized_justified_checkpoint: block.unrealized_justified_checkpoint,
                weight: 0,
                viable: false,
                best_descendant: block.root,
            },
        );
        self.update_node(block.root);
        self.update_ancestors(block.parent_root);
        Ok(())
    }

    /// Adds `delta` to the weight of `root` and of each of its ancestors, then refreshes the
    /// best-descendant pointers along that chain. Unknown roots are ignored: a vote for a block
    /// outside the tree cannot influence any node in it.
    pub fn apply_weight_delta(&mut self, root: B256, delta: i128) {
        if delta == 0 {
            return;
        }
        let mut chain = vec![];
        let mut cursor = Some(root);
        while let Some(current) = cursor {
            let Some(node) = self.nodes.get_mut(&current) else {
                break;
            };
            node.weight = apply_signed(node.weight, delta);
            chain.push(current);
            cursor = node.parent;
        }
        for current in chain {
            self.update_node(current);
        }
    }

    /// Records new latest messages (`validator index -> voted block root`). Equivocating
    /// validators are ignored, as in `update_latest_messages`.
    pub fn process_votes(&mut self, updates: impl IntoIterator<Item = (u64, B256)>) {
        let mut deltas: HashMap<B256, i128> = HashMap::default();
        for (validator_index, root) in updates {
            if self.equivocating.contains(&validator_index) {
                continue;
            }
            let balance = self.balance_of(validator_index);
            if let Some(previous) = self.votes.get(&validator_index) {
                *deltas.entry(previous.root).or_default() -= i128::from(previous.balance);
            }
            *deltas.entry(root).or_default() += i128::from(balance);
            self.votes
                .insert(validator_index, AppliedVote { root, balance });
        }
        self.apply_deltas(deltas);
    }

    /// Removes the influence of equivocating validators, now and for later votes.
    pub fn mark_equivocating(&mut self, indices: impl IntoIterator<Item = u64>) {
        let mut deltas: HashMap<B256, i128> = HashMap::default();
        for validator_index in indices {
            if !self.equivocating.insert(validator_index) {
                continue;
            }
            if let Some(vote) = self.votes.get_mut(&validator_index) {
                *deltas.entry(vote.root).or_default() -= i128::from(vote.balance);
                vote.balance = 0;
            }
        }
        self.apply_deltas(deltas);
    }

    /// Replaces the validator balances (derived from the justified checkpoint state) and re-weights
    /// every counted vote and the proposer boost accordingly.
    pub fn set_balances(
        &mut self,
        checkpoint: Checkpoint,
        balances: Vec<u64>,
        proposer_score: u64,
    ) {
        self.balances = balances;
        self.balances_checkpoint = Some(checkpoint);

        let mut deltas: HashMap<B256, i128> = HashMap::default();
        for (validator_index, vote) in self.votes.iter_mut() {
            let balance = if self.equivocating.contains(validator_index) {
                0
            } else {
                usize::try_from(*validator_index)
                    .ok()
                    .and_then(|index| self.balances.get(index))
                    .copied()
                    .unwrap_or(0)
            };
            if balance != vote.balance {
                *deltas.entry(vote.root).or_default() +=
                    i128::from(balance) - i128::from(vote.balance);
                vote.balance = balance;
            }
        }
        self.apply_deltas(deltas);

        let boost_root = self.boost.map(|(root, _)| root);
        self.proposer_score = proposer_score;
        self.set_proposer_boost_root(boost_root);
    }

    /// Sets (or clears) the block that receives the proposer score boost.
    pub fn set_proposer_boost_root(&mut self, root: Option<B256>) {
        let desired = root.map(|root| (root, self.proposer_score));
        if desired == self.boost {
            return;
        }
        if let Some((old_root, old_score)) = self.boost.take() {
            self.apply_weight_delta(old_root, -i128::from(old_score));
        }
        if let Some((new_root, score)) = desired {
            self.apply_weight_delta(new_root, i128::from(score));
        }
        self.boost = desired;
    }

    /// Updates the values viability depends on. Recomputes every node's viability and
    /// best-descendant pointer when any of them changed.
    pub fn update_context(&mut self, context: ViabilityContext) {
        if context == self.context {
            return;
        }
        self.context = context;
        self.recompute_all();
    }

    /// Re-roots the tree at `new_root` (the newly finalized block), dropping every node that is
    /// not one of its descendants. Subtree weights of retained nodes are unaffected.
    pub fn prune(&mut self, new_root: B256) -> anyhow::Result<()> {
        if new_root == self.root {
            return Ok(());
        }
        ensure!(
            self.nodes.contains_key(&new_root),
            "new finalized root {new_root} is not in the tree"
        );

        let mut retained: HashMap<B256, ForkChoiceNode> = HashMap::default();
        let mut pending = vec![new_root];
        while let Some(current) = pending.pop() {
            if let Some(node) = self.nodes.remove(&current) {
                pending.extend(node.children.iter().copied());
                retained.insert(current, node);
            }
        }
        if let Some(node) = retained.get_mut(&new_root) {
            node.parent = None;
        }
        self.nodes = retained;
        self.root = new_root;
        if self
            .boost
            .is_some_and(|(root, _)| !self.nodes.contains_key(&root))
        {
            self.boost = None;
        }
        self.recompute_all();
        Ok(())
    }

    fn apply_deltas(&mut self, deltas: HashMap<B256, i128>) {
        for (root, delta) in deltas {
            self.apply_weight_delta(root, delta);
        }
    }

    fn balance_of(&self, validator_index: u64) -> u64 {
        if self.equivocating.contains(&validator_index) {
            return 0;
        }
        usize::try_from(validator_index)
            .ok()
            .and_then(|index| self.balances.get(index))
            .copied()
            .unwrap_or(0)
    }

    fn update_ancestors(&mut self, from: B256) {
        let mut cursor = Some(from);
        while let Some(current) = cursor {
            cursor = self.nodes.get(&current).and_then(|node| node.parent);
            self.update_node(current);
        }
    }

    /// Children have strictly greater slots than their parents, so visiting nodes by descending
    /// slot refreshes every child before its parent.
    fn recompute_all(&mut self) {
        let mut order = self
            .nodes
            .iter()
            .map(|(root, node)| (node.slot, *root))
            .collect::<Vec<_>>();
        order.sort_unstable_by(|a, b| b.cmp(a));
        for (_, root) in order {
            self.update_node(root);
        }
    }

    /// Recomputes `viable` and `best_descendant` of one node from its children.
    fn update_node(&mut self, root: B256) {
        let Some(node) = self.nodes.get(&root) else {
            return;
        };

        let (viable, best_descendant) = if node.children.is_empty() {
            (self.is_leaf_viable(root, node), root)
        } else {
            // Highest weight wins; ties go to the lexicographically higher root.
            let best_child = node
                .children
                .iter()
                .filter_map(|child| self.nodes.get(child).map(|value| (child, value)))
                .filter(|(_, child_node)| child_node.viable)
                .max_by_key(|(child_root, child_node)| (child_node.weight, **child_root))
                .map(|(_, child_node)| child_node.best_descendant);
            match best_child {
                Some(best) => (true, best),
                None => (false, root),
            }
        };

        if let Some(node) = self.nodes.get_mut(&root) {
            node.viable = viable;
            node.best_descendant = best_descendant;
        }
    }

    /// Mirrors the leaf branch of the spec's `filter_block_tree`.
    fn is_leaf_viable(&self, root: B256, node: &ForkChoiceNode) -> bool {
        let context = &self.context;
        let voting_source = if context.current_epoch > compute_epoch_at_slot(node.slot) {
            // The block is from a prior epoch, the voting source is pulled up.
            node.unrealized_justified_checkpoint
        } else {
            node.justified_checkpoint
        };

        let correct_justified = context.justified_checkpoint.epoch == GENESIS_EPOCH
            || voting_source.epoch == context.justified_checkpoint.epoch
            || voting_source.epoch + 2 >= context.current_epoch;

        let correct_finalized = context.finalized_checkpoint.epoch == GENESIS_EPOCH
            || self.checkpoint_block(
                root,
                compute_start_slot_at_epoch(context.finalized_checkpoint.epoch),
            ) == context.finalized_checkpoint.root;

        correct_justified && correct_finalized
    }

    /// Ancestor of `root` at or before `slot`, stopping at the tree root.
    fn checkpoint_block(&self, mut root: B256, slot: u64) -> B256 {
        while let Some(node) = self.nodes.get(&root) {
            if node.slot <= slot {
                break;
            }
            match node.parent {
                Some(parent) => root = parent,
                None => break,
            }
        }
        root
    }
}

fn apply_signed(value: u64, delta: i128) -> u64 {
    let updated = i128::from(value) + delta;
    debug_assert!(updated >= 0, "fork choice weight underflow");
    u64::try_from(updated.max(0)).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(byte: u8) -> B256 {
        B256::repeat_byte(byte)
    }

    fn checkpoint(epoch: u64, byte: u8) -> Checkpoint {
        Checkpoint {
            epoch,
            root: root(byte),
        }
    }

    fn block(byte: u8, parent: u8, slot: u64) -> ForkChoiceBlock {
        ForkChoiceBlock {
            root: root(byte),
            parent_root: root(parent),
            slot,
            justified_checkpoint: checkpoint(0, 1),
            unrealized_justified_checkpoint: checkpoint(0, 1),
        }
    }

    fn genesis_context() -> ViabilityContext {
        ViabilityContext {
            justified_checkpoint: checkpoint(0, 1),
            finalized_checkpoint: checkpoint(0, 1),
            current_epoch: 0,
        }
    }

    fn tree_with_balances(validators: usize) -> ForkChoiceTree {
        let mut tree = ForkChoiceTree::new(block(1, 0, 0), genesis_context());
        tree.set_balances(checkpoint(0, 1), vec![32; validators], 0);
        tree
    }

    #[test]
    fn head_follows_chain_tip() {
        let mut tree = tree_with_balances(4);
        assert_eq!(tree.head(), root(1));
        tree.insert(block(2, 1, 1)).unwrap();
        tree.insert(block(3, 2, 2)).unwrap();
        assert_eq!(tree.head(), root(3));
    }

    #[test]
    fn ties_break_towards_higher_root() {
        let mut tree = tree_with_balances(4);
        tree.insert(block(2, 1, 1)).unwrap();
        tree.insert(block(3, 1, 1)).unwrap();
        assert_eq!(tree.head(), root(3));
    }

    #[test]
    fn votes_move_the_head_and_weights_are_subtree_sums() {
        let mut tree = tree_with_balances(4);
        tree.insert(block(2, 1, 1)).unwrap();
        tree.insert(block(3, 1, 1)).unwrap();
        tree.insert(block(4, 2, 2)).unwrap();

        tree.process_votes([(0, root(4)), (1, root(4))]);
        assert_eq!(tree.head(), root(4));
        assert_eq!(tree.weight(&root(2)), Some(64));
        assert_eq!(tree.weight(&root(1)), Some(64));
        assert_eq!(tree.weight(&root(3)), Some(0));

        // Two validators move to the other branch, which now outweighs it and wins.
        tree.process_votes([(0, root(3)), (1, root(3)), (2, root(3))]);
        assert_eq!(tree.head(), root(3));
        assert_eq!(tree.weight(&root(2)), Some(0));
        assert_eq!(tree.weight(&root(3)), Some(96));
    }

    #[test]
    fn equivocating_validators_lose_their_weight() {
        let mut tree = tree_with_balances(4);
        tree.insert(block(2, 1, 1)).unwrap();
        tree.insert(block(3, 1, 1)).unwrap();
        tree.process_votes([(0, root(2)), (1, root(2)), (2, root(3))]);
        assert_eq!(tree.head(), root(2));

        tree.mark_equivocating([0, 1]);
        assert_eq!(tree.head(), root(3));
        assert_eq!(tree.weight(&root(2)), Some(0));

        // Later votes from equivocating validators are ignored.
        tree.process_votes([(0, root(2))]);
        assert_eq!(tree.weight(&root(2)), Some(0));
    }

    #[test]
    fn balance_changes_reweight_existing_votes() {
        let mut tree = tree_with_balances(2);
        tree.insert(block(2, 1, 1)).unwrap();
        tree.insert(block(3, 1, 1)).unwrap();
        tree.process_votes([(0, root(2)), (1, root(3))]);
        // Equal weight, higher root wins.
        assert_eq!(tree.head(), root(3));

        tree.set_balances(checkpoint(0, 2), vec![64, 32], 0);
        assert_eq!(tree.head(), root(2));
        assert_eq!(tree.weight(&root(2)), Some(64));
        assert_eq!(tree.balances_checkpoint(), Some(checkpoint(0, 2)));
    }

    #[test]
    fn proposer_boost_is_applied_along_the_chain_and_removed() {
        let mut tree = tree_with_balances(2);
        tree.insert(block(2, 1, 1)).unwrap();
        tree.insert(block(3, 1, 1)).unwrap();
        tree.set_balances(checkpoint(0, 1), vec![32; 2], 40);
        tree.process_votes([(0, root(3))]);

        tree.set_proposer_boost_root(Some(root(2)));
        assert_eq!(tree.weight(&root(2)), Some(40));
        assert_eq!(tree.weight(&root(1)), Some(72));
        assert_eq!(tree.head(), root(2));

        tree.set_proposer_boost_root(None);
        assert_eq!(tree.weight(&root(2)), Some(0));
        assert_eq!(tree.head(), root(3));
    }

    #[test]
    fn prune_reroots_and_keeps_subtree_weights() {
        let mut tree = tree_with_balances(2);
        tree.insert(block(2, 1, 1)).unwrap();
        tree.insert(block(3, 1, 1)).unwrap();
        tree.insert(block(4, 2, 2)).unwrap();
        tree.process_votes([(0, root(4)), (1, root(3))]);

        tree.prune(root(2)).unwrap();
        assert_eq!(tree.root(), root(2));
        assert!(!tree.contains(&root(1)));
        assert!(!tree.contains(&root(3)));
        assert_eq!(tree.weight(&root(2)), Some(32));

        // A later vote for a pruned block is harmless.
        tree.process_votes([(1, root(3))]);
        assert_eq!(tree.weight(&root(2)), Some(32));
        assert!(tree.prune(root(9)).is_err());
    }

    #[test]
    fn insert_requires_known_parent_and_increasing_slot() {
        let mut tree = tree_with_balances(1);
        assert!(tree.insert(block(2, 9, 1)).is_err());
        assert!(tree.insert(block(2, 1, 0)).is_err());
        tree.insert(block(2, 1, 1)).unwrap();
        // Idempotent.
        tree.insert(block(2, 1, 1)).unwrap();
        assert_eq!(tree.len(), 2);
    }

    #[test]
    fn leaves_with_stale_voting_source_are_not_viable() {
        // Justified epoch 2; the heavier branch's leaf still votes from epoch 0.
        let context = ViabilityContext {
            justified_checkpoint: checkpoint(2, 1),
            finalized_checkpoint: checkpoint(0, 1),
            current_epoch: 5,
        };
        let mut tree = ForkChoiceTree::new(block(1, 0, 0), context);
        tree.set_balances(checkpoint(2, 1), vec![32; 2], 0);

        let stale = ForkChoiceBlock {
            unrealized_justified_checkpoint: checkpoint(0, 1),
            ..block(2, 1, 1)
        };
        let fresh = ForkChoiceBlock {
            unrealized_justified_checkpoint: checkpoint(2, 1),
            ..block(3, 1, 1)
        };
        tree.insert(stale).unwrap();
        tree.insert(fresh).unwrap();
        tree.process_votes([(0, root(2)), (1, root(2))]);

        assert_eq!(tree.head(), root(3));

        // Once the current epoch drops back so that epoch 0 is within two epochs, it is viable.
        tree.update_context(ViabilityContext {
            current_epoch: 2,
            ..context
        });
        assert_eq!(tree.head(), root(2));
    }

    #[test]
    fn leaf_whose_epoch_boundary_block_is_not_the_finalized_block_is_not_viable() {
        // Finalized checkpoint (epoch 1, root 1) sits on the block at slot 30, because slots 31 and
        // 32 were skipped on the finalized chain. A child at slot 31 is at or before the epoch 1
        // boundary (slot 32), so on that child's chain the checkpoint block is the child itself.
        let context = ViabilityContext {
            justified_checkpoint: checkpoint(1, 1),
            finalized_checkpoint: checkpoint(1, 1),
            current_epoch: 1,
        };
        let voting_source = checkpoint(1, 1);
        let at = |byte: u8, slot: u64| ForkChoiceBlock {
            root: root(byte),
            parent_root: root(1),
            slot,
            justified_checkpoint: voting_source,
            unrealized_justified_checkpoint: voting_source,
        };
        let mut tree = ForkChoiceTree::new(
            ForkChoiceBlock {
                slot: 30,
                ..at(1, 30)
            },
            context,
        );
        tree.set_balances(checkpoint(1, 1), vec![32; 2], 0);
        tree.insert(at(9, 31)).unwrap();
        tree.insert(at(2, 33)).unwrap();
        tree.process_votes([(0, root(9)), (1, root(9))]);

        // Root 9 is heavier and has the higher root, but is not viable.
        assert_eq!(tree.head(), root(2));
    }

    #[test]
    fn missing_justified_root_falls_back_to_the_justified_root() {
        let mut context = genesis_context();
        context.justified_checkpoint = checkpoint(0, 7);
        let tree = ForkChoiceTree::new(block(1, 0, 0), context);
        assert_eq!(tree.head(), root(7));
    }

    // ---- Differential test against a from-scratch reference implementation ----

    struct Lcg(u64);

    impl Lcg {
        fn next(&mut self, bound: u64) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (self.0 >> 33) % bound
        }
    }

    /// Spec-shaped reference: recompute every weight and walk the filtered tree from scratch.
    fn reference_head(
        blocks: &[ForkChoiceBlock],
        votes: &HashMap<u64, (B256, u64)>,
        boost: Option<(B256, u64)>,
        context: &ViabilityContext,
        justified_root: B256,
    ) -> B256 {
        let parent_of = |root: B256| {
            blocks
                .iter()
                .find(|block| block.root == root)
                .map(|block| block.parent_root)
        };
        let mut weights: HashMap<B256, u64> = HashMap::default();
        let mut add_chain = |mut current: B256, amount: u64| {
            loop {
                if !blocks.iter().any(|block| block.root == current) {
                    break;
                }
                *weights.entry(current).or_default() += amount;
                match parent_of(current) {
                    Some(parent) => current = parent,
                    None => break,
                }
            }
        };
        for (vote_root, balance) in votes.values() {
            add_chain(*vote_root, *balance);
        }
        if let Some((boost_root, score)) = boost {
            add_chain(boost_root, score);
        }

        fn viable(blocks: &[ForkChoiceBlock], context: &ViabilityContext, root: B256) -> bool {
            let children = blocks
                .iter()
                .filter(|block| block.parent_root == root)
                .map(|block| block.root)
                .collect::<Vec<_>>();
            if !children.is_empty() {
                return children
                    .into_iter()
                    .any(|child| viable(blocks, context, child));
            }
            let block = blocks.iter().find(|block| block.root == root).unwrap();
            let voting_source = if context.current_epoch > compute_epoch_at_slot(block.slot) {
                block.unrealized_justified_checkpoint
            } else {
                block.justified_checkpoint
            };
            context.justified_checkpoint.epoch == GENESIS_EPOCH
                || voting_source.epoch == context.justified_checkpoint.epoch
                || voting_source.epoch + 2 >= context.current_epoch
        }

        let mut head = justified_root;
        loop {
            let best = blocks
                .iter()
                .filter(|block| block.parent_root == head && viable(blocks, context, block.root))
                .map(|block| (weights.get(&block.root).copied().unwrap_or(0), block.root))
                .max();
            match best {
                Some((_, child)) => head = child,
                None => return head,
            }
        }
    }

    #[test]
    fn matches_reference_under_random_operations() {
        for seed in 0..40u64 {
            let mut rng = Lcg(seed + 1);
            let validators = 24u64;
            let anchor = ForkChoiceBlock {
                root: root(1),
                parent_root: root(0),
                slot: 0,
                justified_checkpoint: checkpoint(0, 1),
                unrealized_justified_checkpoint: checkpoint(0, 1),
            };
            let mut context = ViabilityContext {
                justified_checkpoint: checkpoint(0, 1),
                finalized_checkpoint: checkpoint(0, 1),
                current_epoch: 0,
            };
            let mut tree = ForkChoiceTree::new(anchor, context);
            let balances = (0..validators).map(|i| 16 + i).collect::<Vec<_>>();
            tree.set_balances(checkpoint(0, 1), balances.clone(), 50);

            let mut blocks = vec![anchor];
            let mut votes: HashMap<u64, (B256, u64)> = HashMap::default();
            let mut equivocating: HashSet<u64> = HashSet::default();
            let mut boost: Option<(B256, u64)> = None;

            for step in 0..120u64 {
                match rng.next(12) {
                    0..=3 => {
                        let parent = blocks[rng.next(blocks.len() as u64) as usize];
                        let new_root = alloy_primitives::keccak256(
                            [seed.to_be_bytes(), step.to_be_bytes()].concat(),
                        );
                        let slot = parent.slot + 1 + rng.next(3);
                        let justified_epoch = rng.next(3);
                        let new_block = ForkChoiceBlock {
                            root: new_root,
                            parent_root: parent.root,
                            slot,
                            justified_checkpoint: Checkpoint {
                                epoch: justified_epoch,
                                root: root(1),
                            },
                            unrealized_justified_checkpoint: Checkpoint {
                                epoch: rng.next(3),
                                root: root(1),
                            },
                        };
                        tree.insert(new_block).unwrap();
                        blocks.push(new_block);
                    }
                    4..=7 => {
                        let count = 1 + rng.next(4);
                        let mut updates = vec![];
                        for _ in 0..count {
                            let validator = rng.next(validators);
                            let target = blocks[rng.next(blocks.len() as u64) as usize].root;
                            updates.push((validator, target));
                        }
                        tree.process_votes(updates.clone());
                        for (validator, target) in updates {
                            if !equivocating.contains(&validator) {
                                votes.insert(validator, (target, balances[validator as usize]));
                            }
                        }
                    }
                    8 => {
                        let validator = rng.next(validators);
                        tree.mark_equivocating([validator]);
                        equivocating.insert(validator);
                        votes.remove(&validator);
                    }
                    10 => {
                        // Finality advances: re-root at a random block.
                        let new_root = blocks[rng.next(blocks.len() as u64) as usize].root;
                        tree.prune(new_root).unwrap();
                        let mut retained: HashSet<B256> = HashSet::default();
                        retained.insert(new_root);
                        loop {
                            let before = retained.len();
                            for block in &blocks {
                                if retained.contains(&block.parent_root) {
                                    retained.insert(block.root);
                                }
                            }
                            if retained.len() == before {
                                break;
                            }
                        }
                        blocks.retain(|block| retained.contains(&block.root));
                        if boost.is_some_and(|(root, _)| !retained.contains(&root)) {
                            boost = None;
                        }
                        context.justified_checkpoint.root = new_root;
                        tree.update_context(context);
                    }
                    _ => {
                        if rng.next(2) == 0 {
                            let target = blocks[rng.next(blocks.len() as u64) as usize].root;
                            tree.set_proposer_boost_root(Some(target));
                            boost = Some((target, 50));
                        } else {
                            tree.set_proposer_boost_root(None);
                            boost = None;
                        }
                        context.current_epoch = rng.next(6);
                        context.justified_checkpoint.epoch = rng.next(3);
                        tree.update_context(context);
                    }
                }

                let expected = reference_head(
                    &blocks,
                    &votes,
                    boost,
                    &context,
                    context.justified_checkpoint.root,
                );
                assert_eq!(tree.head(), expected, "seed {seed}, step {step}");
            }
        }
    }
}
