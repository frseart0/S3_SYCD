package com.duoc.backend.Medication;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class MedicationControllerTest {

    @Mock
    private MedicationService medicationService;

    @InjectMocks
    private MedicationController medicationController;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void getAllMedications_returnsList() {
        Medication m = new Medication("m", 5);
        m.setId(1L);
        when(medicationService.getAllMedications()).thenReturn(Arrays.asList(m));

        List<Medication> result = medicationController.getAllMedications();

        assertEquals(1, result.size());
        verify(medicationService).getAllMedications();
    }

    @Test
    void getMedicationById_delegates() {
        Medication m = new Medication("n", 6);
        when(medicationService.getMedicationById(2L)).thenReturn(m);

        assertSame(m, medicationController.getMedicationById(2L));
    }

    @Test
    void saveMedication_delegates() {
        Medication input = new Medication("o", 7);
        Medication saved = new Medication("o", 7);
        saved.setId(3L);
        when(medicationService.saveMedication(input)).thenReturn(saved);

        assertEquals(3L, medicationController.saveMedication(input).getId());
    }

    @Test
    void deleteMedication_delegates() {
        medicationController.deleteMedication(8L);
        verify(medicationService).deleteMedication(8L);
    }
}
