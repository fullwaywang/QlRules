/**
 * @name ghostscript-67d760ab775dae4efe803b5944b0439aa3c0b04a-znumicc_components
 * @id cpp/ghostscript/67d760ab775dae4efe803b5944b0439aa3c0b04a/znumicc-components
 * @description ghostscript-67d760ab775dae4efe803b5944b0439aa3c0b04a-psi/zicc.c-znumicc_components CVE-2018-19476
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vpnval_483, AddressOfExpr target_1, ExprStmt target_2, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="type_attrs"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="tas"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpnval_483
		and target_0.getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and (func.getEntryPoint().(BlockStmt).getStmt(11)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(11).getFollowingStmt()=target_0)
		and target_1.getOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vpnval_483, AddressOfExpr target_1) {
		target_1.getOperand().(VariableAccess).getTarget()=vpnval_483
}

predicate func_2(Variable vpnval_483, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
		and target_2.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getTarget().getName()="intval"
		and target_2.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="value"
		and target_2.getExpr().(AssignExpr).getRValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpnval_483
}

from Function func, Variable vpnval_483, AddressOfExpr target_1, ExprStmt target_2
where
not func_0(vpnval_483, target_1, target_2, func)
and func_1(vpnval_483, target_1)
and func_2(vpnval_483, target_2)
and vpnval_483.getType().hasName("ref *")
and vpnval_483.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
