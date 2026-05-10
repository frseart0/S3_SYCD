package com.duoc.backend.Invoice;

import com.duoc.backend.Care.Care;
import com.duoc.backend.Care.CareRepository;
import com.duoc.backend.Medication.Medication;
import com.duoc.backend.Medication.MedicationRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.time.LocalDate;
import java.util.Arrays;
import java.util.Collections;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class InvoiceServiceTest {

    @Mock
    private InvoiceRepository invoiceRepository;

    @Mock
    private MedicationRepository medicationRepository;

    @Mock
    private CareRepository careRepository;

    @InjectMocks
    private InvoiceService invoiceService;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void getAllInvoices_delegates() {
        when(invoiceRepository.findAll()).thenReturn(Collections.emptyList());
        assertNotNull(invoiceService.getAllInvoices());
        verify(invoiceRepository).findAll();
    }

    @Test
    void getInvoiceById_found() {
        Invoice inv = new Invoice(1L, "P", LocalDate.now(), Collections.emptyList(), Collections.emptyList());
        when(invoiceRepository.findById(1L)).thenReturn(Optional.of(inv));
        assertSame(inv, invoiceService.getInvoiceById(1L));
    }

    @Test
    void getInvoiceById_missing() {
        when(invoiceRepository.findById(2L)).thenReturn(Optional.empty());
        assertNull(invoiceService.getInvoiceById(2L));
    }

    @Test
    void saveInvoice_setsTotalAndSavesWhenReferencesValid() {
        Care care = new Care("Consulta", 40);
        care.setId(10L);
        Medication med = new Medication("Jarabe", 15);
        med.setId(20L);
        Invoice invoice = new Invoice(null, "Ana", LocalDate.now(), Arrays.asList(care), Arrays.asList(med));

        when(medicationRepository.findAllById(any())).thenReturn(Arrays.asList(med));
        when(careRepository.findAllById(any())).thenReturn(Arrays.asList(care));
        when(invoiceRepository.save(invoice)).thenAnswer(i -> i.getArgument(0));

        Invoice saved = invoiceService.saveInvoice(invoice);

        assertEquals(55.0, saved.getTotalCost());
        verify(invoiceRepository).save(invoice);
    }

    @Test
    void saveInvoice_throwsWhenMedicationMissing() {
        Care care = new Care("C", 1);
        care.setId(1L);
        Medication med = new Medication("M", 2);
        med.setId(2L);
        Invoice invoice = new Invoice(null, "B", LocalDate.now(), Arrays.asList(care), Arrays.asList(med));

        when(medicationRepository.findAllById(any())).thenReturn(Collections.emptyList());
        when(careRepository.findAllById(any())).thenReturn(Arrays.asList(care));

        assertThrows(IllegalArgumentException.class, () -> invoiceService.saveInvoice(invoice));
        verify(invoiceRepository, never()).save(any());
    }

    @Test
    void saveInvoice_throwsWhenCareMissing() {
        Care care = new Care("C", 1);
        care.setId(1L);
        Medication med = new Medication("M", 2);
        med.setId(2L);
        Invoice invoice = new Invoice(null, "B", LocalDate.now(), Arrays.asList(care), Arrays.asList(med));

        when(medicationRepository.findAllById(any())).thenReturn(Arrays.asList(med));
        when(careRepository.findAllById(any())).thenReturn(Collections.emptyList());

        assertThrows(IllegalArgumentException.class, () -> invoiceService.saveInvoice(invoice));
        verify(invoiceRepository, never()).save(any());
    }

    @Test
    void deleteInvoice_delegates() {
        invoiceService.deleteInvoice(7L);
        verify(invoiceRepository).deleteById(7L);
    }
}
