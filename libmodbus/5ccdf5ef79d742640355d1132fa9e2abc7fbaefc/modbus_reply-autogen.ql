/**
 * @name libmodbus-5ccdf5ef79d742640355d1132fa9e2abc7fbaefc-modbus_reply
 * @id cpp/libmodbus/5ccdf5ef79d742640355d1132fa9e2abc7fbaefc/modbus-reply
 * @description libmodbus-5ccdf5ef79d742640355d1132fa9e2abc7fbaefc-src/modbus.c-modbus_reply CVE-2019-14462
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vnb_841, BlockStmt target_4, LogicalOrExpr target_2) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand() instanceof LogicalOrExpr
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(MulExpr).getLeftOperand().(VariableAccess).getType().hasName("int")
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(MulExpr).getRightOperand().(Literal).getValue()="8"
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vnb_841
		and target_0.getParent().(IfStmt).getThen()=target_4
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_2.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vnb_872, BlockStmt target_5, LogicalOrExpr target_3) {
	exists(LogicalOrExpr target_1 |
		target_1.getAnOperand() instanceof LogicalOrExpr
		and target_1.getAnOperand().(RelationalOperation).getLesserOperand().(MulExpr).getLeftOperand().(VariableAccess).getType().hasName("int")
		and target_1.getAnOperand().(RelationalOperation).getLesserOperand().(MulExpr).getRightOperand().(Literal).getValue()="8"
		and target_1.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vnb_872
		and target_1.getParent().(IfStmt).getThen()=target_5
		and target_1.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_3.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation()))
}

predicate func_2(Variable vnb_841, BlockStmt target_4, LogicalOrExpr target_2) {
		target_2.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vnb_841
		and target_2.getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="1"
		and target_2.getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="1968"
		and target_2.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vnb_841
		and target_2.getParent().(IfStmt).getThen()=target_4
}

predicate func_3(Variable vnb_872, BlockStmt target_5, LogicalOrExpr target_3) {
		target_3.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vnb_872
		and target_3.getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="1"
		and target_3.getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="123"
		and target_3.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vnb_872
		and target_3.getParent().(IfStmt).getThen()=target_5
}

predicate func_4(Variable vnb_841, BlockStmt target_4) {
		target_4.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("response_exception")
		and target_4.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(Literal).getValue()="1"
		and target_4.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(StringLiteral).getValue()="Illegal number of values %d in write_bits (max %d)\n"
		and target_4.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vnb_841
		and target_4.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(7).(Literal).getValue()="1968"
}

predicate func_5(Variable vnb_872, BlockStmt target_5) {
		target_5.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("response_exception")
		and target_5.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(Literal).getValue()="1"
		and target_5.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(5).(StringLiteral).getValue()="Illegal number of values %d in write_registers (max %d)\n"
		and target_5.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vnb_872
		and target_5.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(7).(Literal).getValue()="123"
}

from Function func, Variable vnb_841, Variable vnb_872, LogicalOrExpr target_2, LogicalOrExpr target_3, BlockStmt target_4, BlockStmt target_5
where
not func_0(vnb_841, target_4, target_2)
and not func_1(vnb_872, target_5, target_3)
and func_2(vnb_841, target_4, target_2)
and func_3(vnb_872, target_5, target_3)
and func_4(vnb_841, target_4)
and func_5(vnb_872, target_5)
and vnb_841.getType().hasName("int")
and vnb_872.getType().hasName("int")
and vnb_841.getParentScope+() = func
and vnb_872.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
