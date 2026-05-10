package com.duoc.backend.Appointment;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.time.LocalDate;
import java.time.LocalTime;
import java.util.Arrays;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class AppointmentServiceTest {

    @Mock
    private AppointmentRepository appointmentRepository;

    @InjectMocks
    private AppointmentService appointmentService;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void getAllAppointments_returnsFromRepository() {
        Appointment a = new Appointment();
        when(appointmentRepository.findAll()).thenReturn(Arrays.asList(a));

        Iterable<Appointment> all = appointmentService.getAllAppointments();

        assertNotNull(all);
        verify(appointmentRepository).findAll();
    }

    @Test
    void getAppointmentById_found() {
        Appointment a = new Appointment();
        a.setId(1L);
        when(appointmentRepository.findById(1L)).thenReturn(Optional.of(a));

        assertSame(a, appointmentService.getAppointmentById(1L));
    }

    @Test
    void getAppointmentById_notFound() {
        when(appointmentRepository.findById(99L)).thenReturn(Optional.empty());

        assertNull(appointmentService.getAppointmentById(99L));
    }

    @Test
    void saveAppointment_persists() {
        Appointment a = new Appointment();
        a.setDate(LocalDate.now());
        a.setTime(LocalTime.now());
        when(appointmentRepository.save(a)).thenReturn(a);

        assertSame(a, appointmentService.saveAppointment(a));
        verify(appointmentRepository).save(a);
    }

    @Test
    void deleteAppointment_callsRepository() {
        appointmentService.deleteAppointment(3L);
        verify(appointmentRepository).deleteById(3L);
    }
}
