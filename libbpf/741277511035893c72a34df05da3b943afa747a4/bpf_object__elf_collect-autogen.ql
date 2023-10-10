/**
 * @name libbpf-741277511035893c72a34df05da3b943afa747a4-bpf_object__elf_collect
 * @id cpp/libbpf/741277511035893c72a34df05da3b943afa747a4/bpf-object--elf-collect
 * @description libbpf-741277511035893c72a34df05da3b943afa747a4-src/libbpf.c-bpf_object__elf_collect CVE-2021-45940
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vobj_3302, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(FunctionCall).getTarget().hasName("elf_getshdrnum")
		and target_0.getCondition().(FunctionCall).getArgument(0).(ValueFieldAccess).getTarget().getName()="elf"
		and target_0.getCondition().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="efile"
		and target_0.getCondition().(FunctionCall).getArgument(0).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vobj_3302
		and target_0.getCondition().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand() instanceof ValueFieldAccess
		and target_0.getThen().(BlockStmt).getStmt(0).(DoStmt).getCondition().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("libbpf_print")
		and target_0.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="libbpf: elf: failed to get the number of sections for %s: %s\n"
		and target_0.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="path"
		and target_0.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(FunctionCall).getTarget().hasName("elf_errmsg")
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-4001"
		and (func.getEntryPoint().(BlockStmt).getStmt(9)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(9).getFollowingStmt()=target_0))
}

/*predicate func_1(Parameter vobj_3302, ValueFieldAccess target_6) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("libbpf_print")
		and target_1.getArgument(1).(StringLiteral).getValue()="libbpf: elf: failed to get the number of sections for %s: %s\n"
		and target_1.getArgument(2).(PointerFieldAccess).getTarget().getName()="path"
		and target_1.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vobj_3302
		and target_1.getArgument(3).(FunctionCall).getTarget().hasName("elf_errmsg")
		and target_1.getArgument(3).(FunctionCall).getArgument(0).(UnaryMinusExpr).getValue()="-1"
		and target_6.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_1.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

*/
/*predicate func_2(Parameter vobj_3302, PointerFieldAccess target_2) {
		target_2.getTarget().getName()="efile"
		and target_2.getQualifier().(VariableAccess).getTarget()=vobj_3302
}

*/
predicate func_3(Parameter vobj_3302, PointerFieldAccess target_3) {
		target_3.getTarget().getName()="efile"
		and target_3.getQualifier().(VariableAccess).getTarget()=vobj_3302
}

predicate func_4(Parameter vobj_3302, ValueFieldAccess target_4) {
		target_4.getTarget().getName()="sec_cnt"
		and target_4.getQualifier().(PointerFieldAccess).getTarget().getName()="efile"
		and target_4.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vobj_3302
}

predicate func_5(Parameter vobj_3302, AssignExpr target_5) {
		target_5.getLValue() instanceof ValueFieldAccess
		and target_5.getRValue().(PointerFieldAccess).getTarget().getName()="e_shnum"
		and target_5.getRValue().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="ehdr"
		and target_5.getRValue().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="efile"
		and target_5.getRValue().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vobj_3302
}

predicate func_6(Parameter vobj_3302, ValueFieldAccess target_6) {
		target_6.getTarget().getName()="elf"
		and target_6.getQualifier().(PointerFieldAccess).getTarget().getName()="efile"
		and target_6.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vobj_3302
}

from Function func, Parameter vobj_3302, PointerFieldAccess target_3, ValueFieldAccess target_4, AssignExpr target_5, ValueFieldAccess target_6
where
not func_0(vobj_3302, func)
and func_3(vobj_3302, target_3)
and func_4(vobj_3302, target_4)
and func_5(vobj_3302, target_5)
and func_6(vobj_3302, target_6)
and vobj_3302.getType().hasName("bpf_object *")
and vobj_3302.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
