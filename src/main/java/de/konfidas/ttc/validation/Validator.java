package de.konfidas.ttc.validation;

import de.konfidas.ttc.tars.LogMessageArchive;

import java.util.Collection;


/**
 *  A Validator validates aspects of TAR-Files. For example the sequence of Signature Counters,
 *  the plausibility of time stamps w.r.t to the Sequence of Signature Counters, or the plausibility of
 *  transaction numbers.
 *
 *  A Validator has a state, that it keeps, so calling validate() multiple times can create different results.
 *  It is meant to be called multiple times with different TAR-files, i.e. first with the first exported TAR, than with the second exported
 *  and so on. This way the plausibility of the validated aspects can be checked over a sequence of TAR-Files, which together form the
 *  complete log message history of a TSE.
 */
public interface Validator {
    public Collection<ValidationException> validate(LogMessageArchive tar);
}
