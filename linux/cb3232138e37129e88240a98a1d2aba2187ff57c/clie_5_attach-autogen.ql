/**
 * @name linux-cb3232138e37129e88240a98a1d2aba2187ff57c-clie_5_attach
 * @id cpp/linux/cb3232138e37129e88240a98a1d2aba2187ff57c/clie-5-attach
 * @description linux-cb3232138e37129e88240a98a1d2aba2187ff57c-clie_5_attach 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_3(Parameter vserial_590) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(FunctionCall).getTarget().hasName("dev_err")
		and target_3.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="dev"
		and target_3.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="interface"
		and target_3.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vserial_590
		and target_3.getExpr().(FunctionCall).getArgument(1).(StringLiteral).getValue()="missing bulk out endpoints\n"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="num_bulk_out"
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vserial_590
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="2")
}

predicate func_5(Parameter vserial_590) {
	exists(PointerFieldAccess target_5 |
		target_5.getTarget().getName()="num_ports"
		and target_5.getQualifier().(VariableAccess).getTarget()=vserial_590)
}

from Function func, Parameter vserial_590
where
not func_3(vserial_590)
and func_5(vserial_590)
and vserial_590.getType().hasName("usb_serial *")
and vserial_590.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
