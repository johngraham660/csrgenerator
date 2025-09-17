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
        assert len(csr_generator.csr) == 1029

    def test_csr_starts_with(self, default_csr_info):
        """Verify the CSR starts with the correct header."""
        csr_generator = CsrGenerator(default_csr_info)
        assert csr_generator.csr.startswith('-----BEGIN CERTIFICATE REQUEST-----')

    def test_csr_ends_with(self, default_csr_info):
        """Verify the CSR ends with the correct footer."""
        csr_generator = CsrGenerator(default_csr_info)
        assert csr_generator.csr.endswith('-----END CERTIFICATE REQUEST-----\n')

    def test_private_key_starts_with(self, default_csr_info):
        """Verify the private key starts with an expected header."""
        csr_generator = CsrGenerator(default_csr_info)
        # Handle variations based on OpenSSL versions
        assert (csr_generator.private_key.startswith('-----BEGIN RSA PRIVATE KEY-----') or
                csr_generator.private_key.startswith('-----BEGIN PRIVATE KEY-----'))

    def test_private_key_ends_with(self, default_csr_info):
        """Verify the private key ends with an expected footer."""
        csr_generator = CsrGenerator(default_csr_info)
        # Handle variations based on OpenSSL versions
        assert (csr_generator.private_key.endswith('-----END RSA PRIVATE KEY-----\n') or
                csr_generator.private_key.endswith('-----END PRIVATE KEY-----\n'))


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
