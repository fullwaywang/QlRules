/**
 * @name ghostscript-c3476dde7743761a4e1d39a631716199b696b880-ref_param_read_signal_error
 * @id cpp/ghostscript/c3476dde7743761a4e1d39a631716199b696b880/ref-param-read-signal-error
 * @description ghostscript-c3476dde7743761a4e1d39a631716199b696b880-psi/iparam.c-ref_param_read_signal_error CVE-2018-15910
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Variable vloc_825, AddressOfExpr target_3, ExprStmt target_2, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(ValueFieldAccess).getTarget().getName()="presult"
		and target_1.getCondition().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vloc_825
		and target_1.getThen() instanceof ExprStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(3)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(3).getFollowingStmt()=target_1)
		and target_3.getOperand().(VariableAccess).getLocation().isBefore(target_1.getCondition().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getCondition().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vcode_822, Variable vloc_825, Function func, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(ValueFieldAccess).getTarget().getName()="presult"
		and target_2.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vloc_825
		and target_2.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vcode_822
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_2
}

predicate func_3(Variable vloc_825, AddressOfExpr target_3) {
		target_3.getOperand().(VariableAccess).getTarget()=vloc_825
}

from Function func, Parameter vcode_822, Variable vloc_825, ExprStmt target_2, AddressOfExpr target_3
where
not func_1(vloc_825, target_3, target_2, func)
and func_2(vcode_822, vloc_825, func, target_2)
and func_3(vloc_825, target_3)
and vcode_822.getType().hasName("int")
and vloc_825.getType().hasName("iparam_loc")
and vcode_822.getFunction() = func
and vloc_825.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
