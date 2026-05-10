package com.duoc.backend.Care;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class CareControllerTest {

    @Mock
    private CareRepository careRepository;

    @InjectMocks
    private CareController careController;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void getAllCares_returnsList() {
        Care c1 = new Care("A", 10);
        c1.setId(1L);
        when(careRepository.findAll()).thenReturn(Arrays.asList(c1));

        List<Care> result = careController.getAllCares();

        assertEquals(1, result.size());
        verify(careRepository).findAll();
    }

    @Test
    void getCareById_found() {
        Care c = new Care("B", 20);
        c.setId(2L);
        when(careRepository.findById(2L)).thenReturn(Optional.of(c));

        assertSame(c, careController.getCareById(2L));
    }

    @Test
    void getCareById_missing() {
        when(careRepository.findById(0L)).thenReturn(Optional.empty());

        assertNull(careController.getCareById(0L));
    }

    @Test
    void saveCare_persists() {
        Care input = new Care("C", 30);
        Care saved = new Care("C", 30);
        saved.setId(3L);
        when(careRepository.save(input)).thenReturn(saved);

        Care result = careController.saveCare(input);

        assertEquals(3L, result.getId());
        verify(careRepository).save(input);
    }

    @Test
    void deleteCare_callsRepository() {
        careController.deleteCare(4L);
        verify(careRepository).deleteById(4L);
    }
}
