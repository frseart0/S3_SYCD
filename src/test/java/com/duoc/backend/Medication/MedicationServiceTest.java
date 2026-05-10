package com.duoc.backend.Medication;

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

class MedicationServiceTest {

    @Mock
    private MedicationRepository medicationRepository;

    @InjectMocks
    private MedicationService medicationService;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void getAllMedications_returnsList() {
        Medication m = new Medication("a", 1);
        when(medicationRepository.findAll()).thenReturn(Arrays.asList(m));

        List<Medication> result = medicationService.getAllMedications();

        assertEquals(1, result.size());
        verify(medicationRepository).findAll();
    }

    @Test
    void getMedicationById_found() {
        Medication m = new Medication("b", 2);
        when(medicationRepository.findById(1L)).thenReturn(Optional.of(m));

        assertSame(m, medicationService.getMedicationById(1L));
    }

    @Test
    void getMedicationById_notFound() {
        when(medicationRepository.findById(2L)).thenReturn(Optional.empty());

        assertNull(medicationService.getMedicationById(2L));
    }

    @Test
    void saveMedication_delegates() {
        Medication m = new Medication("c", 3);
        when(medicationRepository.save(m)).thenReturn(m);

        assertSame(m, medicationService.saveMedication(m));
    }

    @Test
    void deleteMedication_delegates() {
        medicationService.deleteMedication(9L);
        verify(medicationRepository).deleteById(9L);
    }
}
