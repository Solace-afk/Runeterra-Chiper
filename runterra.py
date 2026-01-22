import streamlit as st

# --- LOGIKA RUNETERRA CIPHER (TIDAK DIUBAH SECARA ALGORITMA) ---
class RuneterraCipher:
    def __init__(self):
        # Mapping Huruf ke Atribut Kartu
        self.alpha_map = {
            'A': '10MT1010CHCA', 'B': '2MT47FLEP', 'C': '10SI96FLEP', 'D': '2MT22CHCA',
            'E': '1IO23FLEP',    'F': '2SH11FLCO', 'G': '2IO21FLRA',  'H': '5SI66CHCA',
            'I': '2BW44FLRA',    'J': '4PZ43CHCA', 'K': '5DM76FLEP',  'L': '2MT32FLRA',
            'M': '0BW35FLRA',    'N': '1PZ33FLRA', 'O': '5SI63FLEP',  'P': '1BW53CHCA',
            'Q': '3DM55CHCA',    'R': '3SI02FLCO', 'S': '3SI21FLRA',  'T': '7DM67FLCO',
            'U': '4PZ54FLRA',    'V': '1SH11FLCO', 'W': '5IO74FLEP',  'X': '2MT72FLEP',
            'Y': '4IO44CHCA',    'Z': '1SH24CHCA'
        }

        # Reverse map untuk dekripsi
        self.reverse_alpha_map = {v: k for k, v in self.alpha_map.items()}

        # Format Angka 1 (Key Ganjil)
        self.num_map_format1 = {
            '0': 'SHBUFPRA', '1': 'SISLGHEP', '2': 'DMFOALCO', '3': 'MTBUMBRA',
            '4': 'IOFADNRA', '5': 'BWFOEONCO', '6': 'DMFACDCO', '7': 'IOSLDREP',
            '8': 'FJBUBFCO', '9': 'SISLTREP'
        }

        # Format Angka 2 (Key Genap)
        self.num_map_format2 = {
            '0': 'RASHFPBU', '1': 'EPSIGHSL', '2': 'CODMALFO', '3': 'RAMTMBBU',
            '4': 'RAIODNFA', '5': 'COBWEONFO', '6': 'CODMCDFA', '7': 'EPIODRSL',
            '8': 'COFJBFBU', '9': 'EPSITRSL'
        }

    def _shift_char(self, char, shift, direction='encrypt'):
        """Melakukan pergeseran karakter (Gronsfeld logic)."""
        if not char.isalnum():
            return char

        shift = shift % 10 if char.isdigit() else shift % 26

        if direction == 'decrypt':
            shift = -shift

        if char.isdigit():
            new_digit = (int(char) + shift) % 10
            return str(new_digit)
        elif char.isalpha():
            base = ord('A')
            char_upper = char.upper()
            return chr((ord(char_upper) - base + shift) % 26 + base)
        return char

    def _sum_digits_mod10(self, text_block):
        """Menjumlahkan semua angka dalam blok teks, lalu di-mod 10."""
        digits = [int(c) for c in text_block if c.isdigit()]
        if not digits:
            return 0
        return sum(digits) % 10

    def encrypt(self, plaintext, key):
        # Kita simpan log proses ke list agar bisa ditampilkan di UI
        logs = []
        logs.append(f"--- PROSES ENKRIPSI ---")
        
        plaintext = plaintext.upper().replace(" ", "")
        key = str(key)

        # IV = Panjang Plaintext mod 10
        iv = len(plaintext) % 10
        logs.append(f"IV (Panjang Plaintext % 10) = {iv}")

        # Cek Key Ganjil/Genap untuk mapping angka
        first_key_digit = int(key[0])
        is_odd_start = (first_key_digit % 2 != 0)
        num_map = self.num_map_format1 if is_odd_start else self.num_map_format2

        encrypted_blocks = []
        prev_block_ciphertext = ""

        for i, char in enumerate(plaintext):
            # 1. Symbolization
            if char.isalpha():
                block = self.alpha_map.get(char, "")
            elif char.isdigit():
                block = num_map.get(char, "")
            else:
                continue

            key_digit = int(key[i % len(key)])

            # 2. Layer 1: Gronsfeld Equipment
            layer1_block = ""
            for c in block:
                layer1_block += self._shift_char(c, key_digit, 'encrypt')

            # 3. Layer 2: Block Chaining
            if i == 0:
                chain_shift = (key_digit + iv) % 10
            else:
                prev_digit_sum = self._sum_digits_mod10(prev_block_ciphertext)
                chain_shift = (key_digit + prev_digit_sum) % 10

            final_block = ""
            for c in layer1_block:
                final_block += self._shift_char(c, chain_shift, 'encrypt')

            logs.append(f"Char '{char}' -> Raw: {block} -> L1: {layer1_block} -> L2(Final): {final_block}")

            encrypted_blocks.append(final_block)
            prev_block_ciphertext = final_block

        return " ".join(encrypted_blocks), logs

    def decrypt(self, ciphertext, key):
        logs = []
        logs.append(f"--- PROSES DEKRIPSI ---")
        
        blocks = ciphertext.split(" ")
        key = str(key)

        # IV dekripsi = Jumlah Blok mod 10
        iv = len(blocks) % 10
        logs.append(f"IV (Jumlah Blok % 10) = {iv}")

        decrypted_text = ""
        prev_block_ciphertext = ""

        for i, block in enumerate(blocks):
            if not block: continue

            key_digit = int(key[i % len(key)])

            # 1. Hitung Shift Layer 2
            if i == 0:
                chain_shift = (key_digit + iv) % 10
            else:
                prev_digit_sum = self._sum_digits_mod10(prev_block_ciphertext)
                chain_shift = (key_digit + prev_digit_sum) % 10

            # 2. Reverse Layer 2
            layer1_block = ""
            for c in block:
                layer1_block += self._shift_char(c, chain_shift, 'decrypt')

            # 3. Reverse Layer 1
            raw_symbol = ""
            for c in layer1_block:
                raw_symbol += self._shift_char(c, key_digit, 'decrypt')

            # 4. Desymbolization
            if raw_symbol in self.reverse_alpha_map:
                decrypted_char = self.reverse_alpha_map[raw_symbol]
            else:
                first_key_digit = int(key[0])
                is_odd_start = (first_key_digit % 2 != 0)
                target_map = self.num_map_format1 if is_odd_start else self.num_map_format2
                reverse_num = {v: k for k, v in target_map.items()}
                decrypted_char = reverse_num.get(raw_symbol, "?")

            logs.append(f"Block: {block} -> Raw: {raw_symbol} -> Char: {decrypted_char}")

            decrypted_text += decrypted_char
            prev_block_ciphertext = block

        return decrypted_text, logs

# --- STREAMLIT UI ---
def main():
    st.set_page_config(page_title="Chained Gronsfeld: Runeterra", page_icon="🃏")
    
    st.title("🃏 Chained Gronsfeld: Runeterra")
    st.markdown("Tools enkripsi/dekripsi menggunakan metode *Block Chaining* & *Gronsfeld* custom.")
    
    cipher = RuneterraCipher()

    # Menggunakan Tabs untuk ganti mode
    tab1, tab2 = st.tabs(["🔒 Enkripsi", "🔓 Dekripsi"])

    # --- TAB ENKRIPSI ---
    with tab1:
        st.subheader("Enkripsi Pesan")
        plain_text = st.text_input("Masukkan Plaintext:", placeholder="Contoh: HELLO")
        key_enc = st.text_input("Masukkan Key Numerik (Enkripsi):", placeholder="Contoh: 12345")

        if st.button("Enkripsi Sekarang"):
            if not plain_text:
                st.warning("Plaintext tidak boleh kosong.")
            elif not key_enc.isdigit():
                st.error("Key harus berupa angka!")
            else:
                try:
                    result, logs = cipher.encrypt(plain_text, key_enc)
                    
                    st.success("Enkripsi Berhasil!")
                    st.text_area("Ciphertext Output:", value=result, height=100)
                    
                    with st.expander("Lihat Detail Proses (Log)"):
                        for log in logs:
                            st.text(log)
                except Exception as e:
                    st.error(f"Terjadi kesalahan: {e}")

    # --- TAB DEKRIPSI ---
    with tab2:
        st.subheader("Dekripsi Pesan")
        cipher_text = st.text_area("Masukkan Ciphertext:", placeholder="Pisahkan blok dengan spasi")
        key_dec = st.text_input("Masukkan Key Numerik (Dekripsi):", placeholder="Contoh: 12345")

        if st.button("Dekripsi Sekarang"):
            if not cipher_text:
                st.warning("Ciphertext tidak boleh kosong.")
            elif not key_dec.isdigit():
                st.error("Key harus berupa angka!")
            else:
                try:
                    result, logs = cipher.decrypt(cipher_text, key_dec)
                    
                    st.success("Dekripsi Berhasil!")
                    st.text_input("Plaintext Output:", value=result)
                    
                    with st.expander("Lihat Detail Proses (Log)"):
                        for log in logs:
                            st.text(log)
                except Exception as e:
                    st.error(f"Terjadi kesalahan: {e}")

if __name__ == "__main__":
    main()
