import cpp

predicate func_0(Function func) {
	exists(StringLiteral target_0 |
		target_0.getValue()="Removing output file: %s"
		and not target_0.getValue()="Removing output file: %s\n"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Parameter vper) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="outfile"
		and target_1.getType().hasName("char *")
		and target_1.getQualifier().(VariableAccess).getTarget()=vper)
}

predicate func_4(Parameter vper) {
	exists(PointerFieldAccess target_4 |
		target_4.getTarget().getName()="outfile"
		and target_4.getType().hasName("char *")
		and target_4.getQualifier().(VariableAccess).getTarget()=vper)
}

from Function func, Variable vouts, Parameter vper
where
func_0(func)
and func_1(vper)
and func_4(vper)
and vouts.getType().hasName("OutStruct *")
and vper.getType().hasName("per_transfer *")
and vouts.getParentScope+() = func
and vper.getParentScope+() = func
select func, vouts, vper
