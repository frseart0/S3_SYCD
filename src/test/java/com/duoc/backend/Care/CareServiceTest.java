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

class CareServiceTest {

    @Mock
    private CareRepository careRepository;

    @InjectMocks
    private CareService careService;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void getAllCares_returnsList() {
        Care c = new Care("x", 1);
        when(careRepository.findAll()).thenReturn(Arrays.asList(c));

        List<Care> result = careService.getAllCares();

        assertEquals(1, result.size());
        verify(careRepository).findAll();
    }

    @Test
    void getCareById_found() {
        Care c = new Care("y", 2);
        when(careRepository.findById(1L)).thenReturn(Optional.of(c));

        assertSame(c, careService.getCareById(1L));
    }

    @Test
    void getCareById_notFound() {
        when(careRepository.findById(2L)).thenReturn(Optional.empty());

        assertNull(careService.getCareById(2L));
    }

    @Test
    void saveCare_delegates() {
        Care c = new Care("z", 3);
        when(careRepository.save(c)).thenReturn(c);

        assertSame(c, careService.saveCare(c));
    }

    @Test
    void deleteCare_delegates() {
        careService.deleteCare(5L);
        verify(careRepository).deleteById(5L);
    }
}
