/**
 * @name libbpf-3a3ef0c1d09e1894740db71cdcb7be0bfd713671-find_prog_by_sec_insn
 * @id cpp/libbpf/3a3ef0c1d09e1894740db71cdcb7be0bfd713671/find-prog-by-sec-insn
 * @description libbpf-3a3ef0c1d09e1894740db71cdcb7be0bfd713671-src/libbpf.c-find_prog_by_sec_insn CVE-2022-3606
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vobj_4112, SubExpr target_1, ExprStmt target_2, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="nr_programs"
		and target_0.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vobj_4112
		and target_0.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(2)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(2).getFollowingStmt()=target_0)
		and target_1.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vobj_4112, SubExpr target_1) {
		target_1.getLeftOperand().(PointerFieldAccess).getTarget().getName()="nr_programs"
		and target_1.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vobj_4112
		and target_1.getRightOperand().(Literal).getValue()="1"
}

predicate func_2(Parameter vobj_4112, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="programs"
		and target_2.getExpr().(AssignExpr).getRValue().(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vobj_4112
}

from Function func, Parameter vobj_4112, SubExpr target_1, ExprStmt target_2
where
not func_0(vobj_4112, target_1, target_2, func)
and func_1(vobj_4112, target_1)
and func_2(vobj_4112, target_2)
and vobj_4112.getType().hasName("const bpf_object *")
and vobj_4112.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
