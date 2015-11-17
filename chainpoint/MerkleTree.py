import hashlib
from collections import OrderedDict
import json
import binascii

# Merkle Tree 
# 
# This follows the standard definition of a Merkle Tree which differs from that
# used by bitcoin internally.  Specifically, when there are an odd number of
# leaves, the odd leaf gets promoted to the parent's level.  Bitcoin by contrast
# doubles the leaf l and puts hash(l+l) in the parent's level.  The definition
# used by bitcoin leads to multiple lists of leaves which result in the same
# root hash.

def sha256(content):
    """Finds the sha256 hash of the bytearray content."""
    if isinstance(content, str):
        content = content.encode('utf-8')
    if isinstance(content, bytes):
        return hashlib.sha256(content).digest()
    raise TypeError('sha256 must be passed bytes or a string, not %s'%type(content));

class MerkleBranch:
    """MerkleBranch is one branch of a Merkle Tree"""
    def __init__(self, left, right, hash_f=sha256):
        """Build a Merkle branch."""
        if not isinstance(left,bytes) or not isinstance(right, bytes):
            raise TypeError("invalid argument.")
        self.left = left
        self.right = right
        self.hash_f = hash_f
        self.parent = hash_f(left + right)

    def contains(self, target):
        return self.left == target or self.right == target

    def get_json(self):
        branch = {
            'parent': binascii.hexlify(self.parent).decode(),
            'left': binascii.hexlify(self.left).decode(),
            'right': binascii.hexlify(self.right).decode(),
        }
        return branch

class MerkleTree:
    def __init__(self, leaves: list = [], hash_f=sha256):
        """Simplistic Merkle tree. Defaults to sha256."""
        self.leaves = []
        self.hash_f = hash_f
        self.tree = []
        self.tree_height = 0
        self.tree_dict = None
        for x in  leaves: self.add_content(x)

    def add_content(self, content):
        """Hashes content and adds it to the leaves."""
        hashed = self.hash_f(content)
        if hashed != None:
            self.leaves.append(hashed)
        else:
            raise TypeError("invalid argument.")

    def add_hash(self, _hash):
        """Adds a single hash to the to the leaves."""
        if type(_hash) == bytes and len(_hash) == 32:
            self.leaves.append(_hash)
        else:
            raise ValueError("Argument is not a sha256 hash.")

    def merkle_root(self):
        """Take a list of hashes, and return the root merkle hash."""
        if len(self.merkle_tree()) == 0:
            return None
        if len(self.tree[0]) < 1:
            return None
        return self.tree[0][0]

    def merkle_tree(self):
        """
        Create a list of lists representing each level of the Merkle Tree.
        The Merkle Root is stored in tree[0][0].
        """
        # check for empty tree
        if len(self.leaves) == 0:
            return self.tree

        # Initialize a copy of the current leaf list to use in this method.
        levels = [[leaf for leaf in self.leaves]]

        while len(levels[-1]) > 1:
            levels.append(self.merkle_pair(levels[-1]))
            if len(levels[-2]) % 2 == 1:
                levels[-2].pop()

        # Reverse the list because tree depth is counted from root to leaves.
        self.tree = levels[::-1]
        self.tree_height = len(self.tree)
        return self.tree

    def create_dictionary(self):
        """
        Create a 
        Get a JSON object representing the Merkle Tree."""
        if self.merkle_root() == None:
            self.tree_dict = OrderedDict()
            return
        root = binascii.hexlify(self.merkle_root()).decode()

        tree_dict = OrderedDict({root:None})

        # Add Merkle Root to the dictionary.
        # If the tree height is 1 or 2, the root node must contain a list.
        # Any parent node containing leaves must contain a list.
        # All other nodes have OrderedDictionary children.
        if self.tree_height < 3:
            tree_dict[root] = []

        if self.tree_height >= 3:
            tree_dict[root] = {}

        level = 1

        # Create a copy of the nested tree list.
        self.tree_copy = [item for item in self.tree]

        # Add all nodes to the final OrderedDictionary Merkle Tree (tree_dict).
        self.add_children(tree_dict, level, root)
        self.tree_dict = tree_dict

    def get_json(self):
        self.create_dictionary()
        # Create a JSON string from the OrderedDictionary Merkle Tree.
        jsondumps = json.dumps(self.tree_dict, ensure_ascii=True)
        return jsondumps

    def get_children(self, level):
        """
        Get the first two children nodes on this level, popping them off the stack.
        """
        rv = []
        if level >= len(self.tree_copy) or len(self.tree_copy[level]) == 0:
            return rv
        rv.append(binascii.hexlify(self.tree_copy[level].pop(0)).decode())
        if len(self.tree_copy[level]) > 0:
            rv.append(binascii.hexlify(self.tree_copy[level].pop(0)).decode())
        return rv

    def add_children(self, parent, level, key):
        """
        Traverse a tree and write jsond object per level.
        """
        # Base case: if we are above the height of the tree, we're done.
        if level > self.tree_height:
            return

        # If the tree height is 1, just set tree_dict to the root node.
        if self.tree_height == 1:
            parent.update({key: {}})
            return

        # Find the children of this parent node.
        children = self.get_children(level)

        # If there are two more levels, children nodes are themselves parents.
        if level < self.tree_height-1:
            # Create a new Ordered Dictionary to store the children nodes, 
            # which are also parent nodes in the tree.
            children_dict = OrderedDict()

            if len(children) == 1:
                children_dict.update({children[0]: {}})
                parent.update({key: children_dict})
                self.add_children(parent[key], level+1, children[0])

            if len(children) == 2:
                children_dict.update({children[0]: {}})
                children_dict.update({children[1]: {}})
                parent.update({key: children_dict})
                self.add_children(parent[key], level+1, children[0])
                self.add_children(parent[key], level+1, children[1])

        # If this is the 2nd to last level, all children are leaf nodes.
        else:
            if len(children) == 1:
                parent.update(OrderedDict({key: [children[0]]}))
            if len(children) == 2:
                parent.update(OrderedDict({key: [children[0], children[1]]}))

            
    def merkle_pair(self, hashes, target=None):
        """
        Take a list of hashes, and return the parent row in the tree
        of merkle hashes. Optionally takes a target hash, and will only
        return part of the tree that corresponds with that hash.
        """
        l = []
        # create an entry in the parent row for each pair in the current row
        for i in range(0, len(hashes)-1, 2):
            parent = self.hash_f(hashes[i] + hashes[i + 1])
            l.append(parent)
            # (optional) if the target hash is in the current row, return
            # only that pair as a MerkleBranch object
            if target == hashes[i] or target == hashes[i + 1]:
                return MerkleBranch(hashes[i], hashes[i + 1], self.hash_f)
        # if odd then append last entry to the end of the parent's list
        if len(hashes) % 2 == 1:
            l.append(hashes[-1])

        if target is None:
            return l  # return the parent row
        else:
            # (optional) the target hash was not found so we return
            # and None (the target may have moved to the parent level
            return None

    def merkle_proof(self, target):
        """Gives the merkle proof of a particular leaf in the root."""

        # Generate list we can mutate
        hashes = self.leaves
        proof = MerkleProof(target, self)

        # Reduce list till we have a merkle root, but extra target
        while len(hashes) > 1:
            branch = self.merkle_pair(hashes, target)
            proof.add(branch)
            target = branch.parent
            hashes = self.merkle_pair(hashes)

        return proof

class MerkleProof:
    def __init__(self, target, tree, hash_f=sha256):
        """Build a Merkle proof."""
        self.hash_f = hash_f
        self.branches = []
        self.target = target
        self.tree = tree

    def add(self, branch):
        """Add a branch to the proof."""
        self.branches.append(branch)

    def is_valid(self):
        """Check if the target hash is in the proof."""

        # If there is only one hash in this proof, return hash == target
        if len(self.tree.leaves) == 1:
            return self.tree.leaves[0] == self.target

        # We assume that the leaf is contained in the first branch of the 
        # proof, so then we check if the parent is contained in each higher
        # branch.

        new_target = self.target
        for branch in self.branches:
            if not branch.contains(new_target):
                return False
            new_target = branch.parent

        return True

    def get_json(self):
        """MerkleProof to machine readable JSON."""
        json_data = [branch.get_json() for branch in self.branches]
        return json.dumps(json_data)

