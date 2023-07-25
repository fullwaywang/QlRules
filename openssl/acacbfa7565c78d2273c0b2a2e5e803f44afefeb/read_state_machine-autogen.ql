/**
 * @name openssl-acacbfa7565c78d2273c0b2a2e5e803f44afefeb-read_state_machine
 * @id cpp/openssl/acacbfa7565c78d2273c0b2a2e5e803f44afefeb/read-state-machine
 * @description openssl-acacbfa7565c78d2273c0b2a2e5e803f44afefeb-ssl/statem/statem.c-read_state_machine CVE-2016-6309
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vs_474, PointerFieldAccess target_4, PointerFieldAccess target_5) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("grow_init_buf")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vs_474
		and target_0.getArgument(1) instanceof AddExpr
		and target_4.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getArgument(0).(VariableAccess).getLocation())
		and target_0.getArgument(0).(VariableAccess).getLocation().isBefore(target_5.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vs_474, AddExpr target_1) {
		target_1.getAnOperand().(ValueFieldAccess).getTarget().getName()="message_size"
		and target_1.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="tmp"
		and target_1.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="s3"
		and target_1.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_474
		and target_1.getAnOperand().(Literal).getValue()="4"
		and target_1.getParent().(FunctionCall).getParent().(NotExpr).getOperand() instanceof FunctionCall
}

predicate func_2(Parameter vs_474, VariableAccess target_2) {
		target_2.getTarget()=vs_474
}

predicate func_3(Parameter vs_474, FunctionCall target_3) {
		target_3.getTarget().hasName("BUF_MEM_grow_clean")
		and target_3.getArgument(0).(PointerFieldAccess).getTarget().getName()="init_buf"
		and target_3.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_474
		and target_3.getArgument(1) instanceof AddExpr
}

predicate func_4(Parameter vs_474, PointerFieldAccess target_4) {
		target_4.getTarget().getName()="tmp"
		and target_4.getQualifier().(PointerFieldAccess).getTarget().getName()="s3"
		and target_4.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_474
}

predicate func_5(Parameter vs_474, PointerFieldAccess target_5) {
		target_5.getTarget().getName()="tmp"
		and target_5.getQualifier().(PointerFieldAccess).getTarget().getName()="s3"
		and target_5.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_474
}

from Function func, Parameter vs_474, AddExpr target_1, VariableAccess target_2, FunctionCall target_3, PointerFieldAccess target_4, PointerFieldAccess target_5
where
not func_0(vs_474, target_4, target_5)
and func_1(vs_474, target_1)
and func_2(vs_474, target_2)
and func_3(vs_474, target_3)
and func_4(vs_474, target_4)
and func_5(vs_474, target_5)
and vs_474.getType().hasName("SSL *")
and vs_474.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
