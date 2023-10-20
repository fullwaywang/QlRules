/**
 * @name postgresql-fcd15f13581f6d75c63d213220d5a94889206c1b-connectDatabase
 * @id cpp/postgresql/fcd15f13581f6d75c63d213220d5a94889206c1b/connectDatabase
 * @description postgresql-fcd15f13581f6d75c63d213220d5a94889206c1b-src/bin/pg_dump/pg_dumpall.c-connectDatabase CVE-2016-5424
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vconn_opt_1890, ExprStmt target_4, PostfixIncrExpr target_5, LogicalAndExpr target_2) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand() instanceof LogicalAndExpr
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("strcmp")
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="keyword"
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_opt_1890
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="dbname"
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getParent().(IfStmt).getThen()=target_4
		and target_5.getOperand().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vconn_opt_1890, BlockStmt target_6, PostfixIncrExpr target_7, LogicalAndExpr target_3) {
	exists(LogicalAndExpr target_1 |
		target_1.getAnOperand() instanceof LogicalAndExpr
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("strcmp")
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="keyword"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_opt_1890
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="dbname"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getParent().(IfStmt).getThen()=target_6
		and target_7.getOperand().(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Variable vconn_opt_1890, ExprStmt target_4, LogicalAndExpr target_2) {
		target_2.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="val"
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_opt_1890
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="val"
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_opt_1890
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="0"
		and target_2.getParent().(IfStmt).getThen()=target_4
}

predicate func_3(Variable vconn_opt_1890, BlockStmt target_6, LogicalAndExpr target_3) {
		target_3.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="val"
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_opt_1890
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="val"
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_opt_1890
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="0"
		and target_3.getParent().(IfStmt).getThen()=target_6
}

predicate func_4(ExprStmt target_4) {
		target_4.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget().getType().hasName("int")
}

predicate func_5(Variable vconn_opt_1890, PostfixIncrExpr target_5) {
		target_5.getOperand().(VariableAccess).getTarget()=vconn_opt_1890
}

predicate func_6(Variable vconn_opt_1890, BlockStmt target_6) {
		target_6.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget().getType().hasName("const char **")
		and target_6.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget().getType().hasName("int")
		and target_6.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="keyword"
		and target_6.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_opt_1890
		and target_6.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget().getType().hasName("const char **")
		and target_6.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget().getType().hasName("int")
		and target_6.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="val"
		and target_6.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_opt_1890
}

predicate func_7(Variable vconn_opt_1890, PostfixIncrExpr target_7) {
		target_7.getOperand().(VariableAccess).getTarget()=vconn_opt_1890
}

from Function func, Variable vconn_opt_1890, LogicalAndExpr target_2, LogicalAndExpr target_3, ExprStmt target_4, PostfixIncrExpr target_5, BlockStmt target_6, PostfixIncrExpr target_7
where
not func_0(vconn_opt_1890, target_4, target_5, target_2)
and not func_1(vconn_opt_1890, target_6, target_7, target_3)
and func_2(vconn_opt_1890, target_4, target_2)
and func_3(vconn_opt_1890, target_6, target_3)
and func_4(target_4)
and func_5(vconn_opt_1890, target_5)
and func_6(vconn_opt_1890, target_6)
and func_7(vconn_opt_1890, target_7)
and vconn_opt_1890.getType().hasName("PQconninfoOption *")
and vconn_opt_1890.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
