/**
 * @name linux-6aeb75e6adfaed16e58780309613a578fe1ee90b-change_port_settings
 * @id cpp/linux/6aeb75e6adfaed16e58780309613a578fe1ee90b/change-port-settings
 * @description linux-6aeb75e6adfaed16e58780309613a578fe1ee90b-change_port_settings 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vbaud_2236) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vbaud_2236
		and target_0.getExpr().(AssignExpr).getRValue().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(VariableAccess).getTarget()=vbaud_2236
		and target_0.getExpr().(AssignExpr).getRValue().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(Literal).getValue()="461550"
		and target_0.getExpr().(AssignExpr).getRValue().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(EqualityOperation).getAnOperand().(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("int")
		and target_0.getExpr().(AssignExpr).getRValue().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(EqualityOperation).getAnOperand().(AddressOfExpr).getOperand().(VariableAccess).getType().hasName("int")
		and target_0.getExpr().(AssignExpr).getRValue().(StmtExpr).getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("int")
		and target_0.getExpr().(AssignExpr).getRValue().(StmtExpr).getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("int")
		and target_0.getExpr().(AssignExpr).getRValue().(StmtExpr).getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(ConditionalExpr).getThen().(VariableAccess).getType().hasName("int")
		and target_0.getExpr().(AssignExpr).getRValue().(StmtExpr).getStmt().(BlockStmt).getStmt(3).(ExprStmt).getExpr().(ConditionalExpr).getElse().(VariableAccess).getType().hasName("int")
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vbaud_2236)
}

predicate func_5(Variable vbaud_2236, Parameter vtty_2231) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(FunctionCall).getTarget().hasName("tty_encode_baud_rate")
		and target_5.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vtty_2231
		and target_5.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vbaud_2236
		and target_5.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vbaud_2236
		and target_5.getParent().(IfStmt).getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vbaud_2236)
}

from Function func, Variable vbaud_2236, Parameter vtty_2231
where
not func_0(vbaud_2236)
and func_5(vbaud_2236, vtty_2231)
and vbaud_2236.getType().hasName("int")
and vtty_2231.getType().hasName("tty_struct *")
and vbaud_2236.getParentScope+() = func
and vtty_2231.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
