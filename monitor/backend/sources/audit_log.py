import json, os

class AuditTailer:
    def __init__(self, path):
        self.path = path
        self.offset = 0
        self.inode = None

    def read_new(self):
        if not os.path.exists(self.path):
            return []
        st = os.stat(self.path)
        if self.inode is None:
            self.inode = st.st_ino
        if st.st_ino != self.inode or st.st_size < self.offset:
            self.offset = 0; self.inode = st.st_ino     # rotated/truncated
        out = []
        with open(self.path, "r") as f:
            f.seek(self.offset)
            for line in f:
                line = line.strip()
                if line:
                    try: out.append(json.loads(line))
                    except json.JSONDecodeError: pass
            self.offset = f.tell()
        return out
