/**
 * @name file-35c94dc6acc418f1ad7f6241a6680e5327495793-do_bid_note
 * @id cpp/file/35c94dc6acc418f1ad7f6241a6680e5327495793/do-bid-note
 * @description file-35c94dc6acc418f1ad7f6241a6680e5327495793-src/readelf.c-do_bid_note CVE-2017-1000249
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(BlockStmt target_4, Function func) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand() instanceof RelationalOperation
		and target_0.getAnOperand() instanceof RelationalOperation
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="4"
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("strcmp")
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="GNU"
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getParent().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="3"
		and target_0.getParent().(LogicalAndExpr).getAnOperand() instanceof LogicalOrExpr
		and target_0.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_4
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Parameter vdescsz_510, RelationalOperation target_1) {
		 (target_1 instanceof GEExpr or target_1 instanceof LEExpr)
		and target_1.getGreaterOperand().(VariableAccess).getTarget()=vdescsz_510
		and target_1.getLesserOperand().(Literal).getValue()="4"
}

predicate func_2(Parameter vdescsz_510, RelationalOperation target_2) {
		 (target_2 instanceof GEExpr or target_2 instanceof LEExpr)
		and target_2.getLesserOperand().(VariableAccess).getTarget()=vdescsz_510
		and target_2.getGreaterOperand().(Literal).getValue()="20"
}

predicate func_3(BlockStmt target_4, Function func, LogicalOrExpr target_3) {
		target_3.getAnOperand() instanceof RelationalOperation
		and target_3.getAnOperand() instanceof RelationalOperation
		and target_3.getParent().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="4"
		and target_3.getParent().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("strcmp")
		and target_3.getParent().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="GNU"
		and target_3.getParent().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_3.getParent().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="3"
		and target_3.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_4
		and target_3.getEnclosingFunction() = func
}

predicate func_4(Parameter vdescsz_510, BlockStmt target_4) {
		target_4.getStmt(3).(ExprStmt).getExpr().(AssignOrExpr).getRValue().(Literal).getValue()="16"
		and target_4.getStmt(4).(BlockStmt).getStmt(0).(SwitchStmt).getExpr().(VariableAccess).getTarget()=vdescsz_510
		and target_4.getStmt(4).(BlockStmt).getStmt(0).(SwitchStmt).getStmt().(BlockStmt).getStmt(0).(SwitchCase).getExpr().(Literal).getValue()="8"
		and target_4.getStmt(4).(BlockStmt).getStmt(0).(SwitchStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(StringLiteral).getValue()="xxHash"
		and target_4.getStmt(4).(BlockStmt).getStmt(0).(SwitchStmt).getStmt().(BlockStmt).getStmt(2).(BreakStmt).toString() = "break;"
		and target_4.getStmt(4).(BlockStmt).getStmt(0).(SwitchStmt).getStmt().(BlockStmt).getStmt(3).(SwitchCase).getExpr().(Literal).getValue()="16"
		and target_4.getStmt(4).(BlockStmt).getStmt(0).(SwitchStmt).getStmt().(BlockStmt).getStmt(4).(ExprStmt).getExpr().(AssignExpr).getRValue().(StringLiteral).getValue()="md5/uuid"
}

from Function func, Parameter vdescsz_510, RelationalOperation target_1, RelationalOperation target_2, LogicalOrExpr target_3, BlockStmt target_4
where
not func_0(target_4, func)
and func_1(vdescsz_510, target_1)
and func_2(vdescsz_510, target_2)
and func_3(target_4, func, target_3)
and func_4(vdescsz_510, target_4)
and vdescsz_510.getType().hasName("uint32_t")
and vdescsz_510.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
