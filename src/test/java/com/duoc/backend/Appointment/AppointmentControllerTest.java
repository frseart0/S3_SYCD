package com.duoc.backend.Appointment;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.time.LocalDate;
import java.time.LocalTime;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class AppointmentControllerTest {

    @Mock
    private AppointmentService appointmentService;

    @InjectMocks
    private AppointmentController appointmentController;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void getAllAppointments_returnsList() {
        Appointment a1 = new Appointment();
        a1.setId(1L);
        Appointment a2 = new Appointment();
        a2.setId(2L);
        when(appointmentService.getAllAppointments()).thenReturn(Arrays.asList(a1, a2));

        List<Appointment> result = appointmentController.getAllAppointments();

        assertEquals(2, result.size());
        verify(appointmentService, times(1)).getAllAppointments();
    }

    @Test
    void getAppointmentById_returnsEntity() {
        Appointment a = new Appointment();
        a.setId(5L);
        a.setDate(LocalDate.of(2026, 5, 10));
        a.setTime(LocalTime.of(10, 30));
        when(appointmentService.getAppointmentById(5L)).thenReturn(a);

        Appointment result = appointmentController.getAppointmentById(5L);

        assertNotNull(result);
        assertEquals(5L, result.getId());
        verify(appointmentService).getAppointmentById(5L);
    }

    @Test
    void saveAppointment_delegatesToService() {
        Appointment input = new Appointment();
        input.setReason("Control");
        Appointment saved = new Appointment();
        saved.setId(1L);
        saved.setReason("Control");
        when(appointmentService.saveAppointment(input)).thenReturn(saved);

        Appointment result = appointmentController.saveAppointment(input);

        assertEquals(1L, result.getId());
        verify(appointmentService).saveAppointment(input);
    }

    @Test
    void deleteAppointment_delegatesToService() {
        appointmentController.deleteAppointment(9L);
        verify(appointmentService).deleteAppointment(9L);
    }
}
