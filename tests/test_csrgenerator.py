import pytest
import OpenSSL.crypto

# Assuming CsrGenerator is available from 'csr.py' in the same directory or PYTHONPATH
from csr import CsrGenerator


@pytest.fixture
def default_csr_info():
    """A pytest fixture providing the standard CSR information dictionary."""
    return {
        'C': 'US',
        'ST': 'Texas',
        'L': 'San Antonio',
        'O': "Big Bob's Beepers",
        'OU': 'Marketing',
        'CN': 'example.com'
    }

class TestCsrGeneration:
    """Tests related to the successful generation of CSRs and keys."""

    def test_keypair_type(self, default_csr_info):
        """Verify the generated keypair is an OpenSSL.crypto.PKey object."""
        csr_generator = CsrGenerator(default_csr_info)
        assert isinstance(csr_generator.keypair, OpenSSL.crypto.PKey)

    @pytest.mark.parametrize("key_size", [2048, 1024, 4096])
    def test_keypair_bits(self, default_csr_info, key_size):
        """Test keypair generation with different bit sizes."""
        csr_info = default_csr_info.copy()
        if key_size != 2048:  # 2048 is the default, no need to explicitly set for it
            csr_info['keySize'] = key_size
        csr_generator = CsrGenerator(csr_info)
        assert csr_generator.keypair.bits() == key_size

    def test_csr_length(self, default_csr_info):
        """Verify the length of the generated CSR string."""
        csr_generator = CsrGenerator(default_csr_info)
        # Note: csr_generator.csr is a bytes object, so len() on it counts bytes.
        # The original test expected 1029. Let's assume this byte length is correct.
        assert len(csr_generator.csr) == 1029

    def test_csr_starts_with(self, default_csr_info):
        """Verify the CSR starts with the correct header."""
        csr_generator = CsrGenerator(default_csr_info)
        expected_start = b'-----BEGIN CERTIFICATE REQUEST-----' # Changed to bytes
        print(f"\n--- Debugging test_csr_starts_with ---")
        print(f"Expected CSR start: '{expected_start}'")
        print(f"Actual CSR start  : '{csr_generator.csr[:len(expected_start) + 5]}...'") # Print start + a few chars
        assert csr_generator.csr.startswith(expected_start)

    def test_csr_ends_with(self, default_csr_info):
        """Verify the CSR ends with the correct footer."""
        csr_generator = CsrGenerator(default_csr_info)
        expected_end = b'-----END CERTIFICATE REQUEST-----\n' # Changed to bytes
        print(f"\n--- Debugging test_csr_ends_with ---")
        print(f"Expected CSR end: '{expected_end}' (length: {len(expected_end)})")
        print(f"Actual CSR end  : '...{csr_generator.csr[-len(expected_end) - 5:]}' (length: {len(csr_generator.csr[-len(expected_end):])})") # Print end + a few chars
        print(f"Actual CSR end (repr): '{repr(csr_generator.csr[-len(expected_end) - 5:])}'")
        assert csr_generator.csr.endswith(expected_end)

    def test_private_key_starts_with(self, default_csr_info):
        """Verify the private key starts with an expected header."""
        csr_generator = CsrGenerator(default_csr_info)
        expected_rsa_start = b'-----BEGIN RSA PRIVATE KEY-----' # Changed to bytes
        expected_pkcs8_start = b'-----BEGIN PRIVATE KEY-----'   # Changed to bytes
        # Use csr_generator.private_key directly for debugging as it's already a byte string
        actual_start_slice = csr_generator.private_key[:len(expected_rsa_start) + 5]
        print(f"\n--- Debugging test_private_key_starts_with ---")
        print(f"Expected RSA start  : '{expected_rsa_start}'")
        print(f"Expected PKCS#8 start: '{expected_pkcs8_start}'")
        print(f"Actual Private Key start (slice): '{actual_start_slice}'")
        assert (csr_generator.private_key.startswith(expected_rsa_start) or
                csr_generator.private_key.startswith(expected_pkcs8_start))

    def test_private_key_ends_with(self, default_csr_info):
        """Verify the private key ends with an expected footer."""
        csr_generator = CsrGenerator(default_csr_info)
        expected_rsa_end = b'-----END RSA PRIVATE KEY-----\n' # Changed to bytes
        expected_pkcs8_end = b'-----END PRIVATE KEY-----\n'   # Changed to bytes
        actual_end = csr_generator.private_key[-len(expected_rsa_end) - 5:] # Take a generous slice from the end
        print(f"\n--- Debugging test_private_key_ends_with ---")
        print(f"Expected RSA end  : '{expected_rsa_end}' (length: {len(expected_rsa_end)})")
        print(f"Expected PKCS#8 end: '{expected_pkcs8_end}' (length: {len(expected_pkcs8_end)})")
        print(f"Actual Private Key end  : '...{actual_end}' (length: {len(csr_generator.private_key[-len(expected_rsa_end):])})")
        print(f"Actual Private Key end (repr): '{repr(csr_generator.private_key[-len(expected_rsa_end) - 5:])}'")

        assert (csr_generator.private_key.endswith(expected_rsa_end) or
                csr_generator.private_key.endswith(expected_pkcs8_end))


class TestCsrExceptionHandling:
    """Tests related to exceptions raised by CsrGenerator."""

    @pytest.mark.parametrize("missing_field", ['C', 'ST', 'L', 'O', 'CN'])
    def test_missing_required_info_raises_key_error(self, default_csr_info, missing_field):
        """Test that missing required fields raise a KeyError."""
        csr_info = default_csr_info.copy()
        del csr_info[missing_field]
        with pytest.raises(KeyError):
            CsrGenerator(csr_info)

    def test_empty_country_raises_key_error(self, default_csr_info):
        """Test that an empty 'C' field raises a KeyError."""
        csr_info = default_csr_info.copy()
        csr_info['C'] = ''
        with pytest.raises(KeyError):
            CsrGenerator(csr_info)

    def test_missing_ou_does_not_raise_exception(self, default_csr_info):
        """Test that missing 'OU' field does NOT raise any exception."""
        csr_info = default_csr_info.copy()
        del csr_info['OU']
        try:
            CsrGenerator(csr_info)
        except Exception as e:
            pytest.fail(f"Unexpected exception raised: {e}")

    def test_empty_ou_does_not_raise_exception(self, default_csr_info):
        """Test that an empty 'OU' field does NOT raise any exception."""
        csr_info = default_csr_info.copy()
        csr_info['OU'] = ''
        try:
            CsrGenerator(csr_info)
        except Exception as e:
            pytest.fail(f"Unexpected exception raised: {e}")

    def test_zero_key_size_raises_key_error(self, default_csr_info):
        """Test that a keySize of 0 raises a KeyError."""
        csr_info = default_csr_info.copy()
        csr_info['keySize'] = 0
        with pytest.raises(KeyError):
            CsrGenerator(csr_info)

    def test_invalid_key_size_raises_value_error(self, default_csr_info):
        """Test that an invalid keySize type raises a ValueError."""
        csr_info = default_csr_info.copy()
        csr_info['keySize'] = 'penguins'
        with pytest.raises(ValueError):
            CsrGenerator(csr_info)
