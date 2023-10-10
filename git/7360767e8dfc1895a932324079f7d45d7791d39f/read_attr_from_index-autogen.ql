/**
 * @name git-7360767e8dfc1895a932324079f7d45d7791d39f-read_attr_from_index
 * @id cpp/git/7360767e8dfc1895a932324079f7d45d7791d39f/read-attr-from-index
 * @description git-7360767e8dfc1895a932324079f7d45d7791d39f-attr.c-read_attr_from_index CVE-2022-41953
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vpath_733) {
	exists(AddressOfExpr target_0 |
		target_0.getOperand().(VariableAccess).getType().hasName("unsigned long")
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("read_blob_data_from_index")
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vpath_733
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(2) instanceof Literal)
}

predicate func_1(Parameter vpath_733, ExprStmt target_3, ExprStmt target_4, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("unsigned long")
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(MulExpr).getValue()="104857600"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("warning")
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("_")
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(StringLiteral).getValue()="ignoring overly large gitattributes blob '%s'"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vpath_733
		and target_1.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr() instanceof Literal
		and (func.getEntryPoint().(BlockStmt).getStmt(8)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(8).getFollowingStmt()=target_1)
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_4.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation()))
}

predicate func_3(Parameter vpath_733, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("read_blob_data_from_index")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vpath_733
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2) instanceof Literal
}

predicate func_4(Parameter vpath_733, ExprStmt target_4) {
		target_4.getExpr().(FunctionCall).getTarget().hasName("handle_attr_line")
		and target_4.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vpath_733
}

from Function func, Parameter vpath_733, ExprStmt target_3, ExprStmt target_4
where
not func_0(vpath_733)
and not func_1(vpath_733, target_3, target_4, func)
and func_3(vpath_733, target_3)
and func_4(vpath_733, target_4)
and vpath_733.getType().hasName("const char *")
and vpath_733.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
