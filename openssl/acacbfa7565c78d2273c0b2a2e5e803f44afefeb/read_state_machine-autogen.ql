import cpp

predicate func_0(Function func) {
	exists(Literal target_0 |
		target_0.getValue()="541"
		and not target_0.getValue()="556"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(Literal target_1 |
		target_1.getValue()="552"
		and not target_1.getValue()="566"
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Function func) {
	exists(Literal target_2 |
		target_2.getValue()="572"
		and not target_2.getValue()="586"
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Function func) {
	exists(Literal target_3 |
		target_3.getValue()="622"
		and not target_3.getValue()="636"
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(Parameter vs) {
	exists(FunctionCall target_4 |
		target_4.getTarget().hasName("grow_init_buf")
		and target_4.getType().hasName("int")
		and target_4.getArgument(0).(VariableAccess).getTarget()=vs
		and target_4.getArgument(1).(AddExpr).getType().hasName("unsigned long")
		and target_4.getArgument(1).(AddExpr).getLeftOperand().(ValueFieldAccess).getTarget().getName()="message_size"
		and target_4.getArgument(1).(AddExpr).getLeftOperand().(ValueFieldAccess).getType().hasName("unsigned long")
		and target_4.getArgument(1).(AddExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="tmp"
		and target_4.getArgument(1).(AddExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getType().hasName("struct <unnamed>")
		and target_4.getArgument(1).(AddExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="s3"
		and target_4.getArgument(1).(AddExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs
		and target_4.getArgument(1).(AddExpr).getRightOperand().(Literal).getValue()="4")
}

predicate func_5(Parameter vs) {
	exists(ValueFieldAccess target_5 |
		target_5.getTarget().getName()="message_size"
		and target_5.getType().hasName("unsigned long")
		and target_5.getQualifier().(PointerFieldAccess).getTarget().getName()="tmp"
		and target_5.getQualifier().(PointerFieldAccess).getType().hasName("struct <unnamed>")
		and target_5.getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="s3"
		and target_5.getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getType().hasName("ssl3_state_st *")
		and target_5.getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs)
}

predicate func_6(Function func) {
	exists(Literal target_6 |
		target_6.getValue()="4"
		and target_6.getEnclosingFunction() = func)
}

predicate func_8(Parameter vs, Function func) {
	exists(FunctionCall target_8 |
		target_8.getTarget().hasName("BUF_MEM_grow_clean")
		and target_8.getType().hasName("size_t")
		and target_8.getArgument(0).(PointerFieldAccess).getTarget().getName()="init_buf"
		and target_8.getArgument(0).(PointerFieldAccess).getType().hasName("BUF_MEM *")
		and target_8.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs
		and target_8.getArgument(1).(AddExpr).getType().hasName("int")
		and target_8.getArgument(1).(AddExpr).getLeftOperand() instanceof ValueFieldAccess
		and target_8.getArgument(1).(AddExpr).getRightOperand() instanceof Literal
		and target_8.getEnclosingFunction() = func)
}

from Function func, Parameter vs
where
func_0(func)
and func_1(func)
and func_2(func)
and func_3(func)
and not func_4(vs)
and func_5(vs)
and func_6(func)
and func_8(vs, func)
and vs.getType().hasName("SSL *")
and vs.getParentScope+() = func
select func, vs
