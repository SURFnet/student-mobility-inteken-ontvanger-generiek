package generic;

import org.junit.jupiter.api.Test;

class GenericApplicationTest {

    @Test
    void main() {
        GenericApplication.main(new String[]{"--server.port=8088"});
    }
}