/**
 * @name postgresql-fcd15f13581f6d75c63d213220d5a94889206c1b-GetConnection
 * @id cpp/postgresql/fcd15f13581f6d75c63d213220d5a94889206c1b/GetConnection
 * @description postgresql-fcd15f13581f6d75c63d213220d5a94889206c1b-src/bin/pg_basebackup/streamutil.c-GetConnection CVE-2016-5424
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(Literal).getValue()="1"
		and (func.getEntryPoint().(BlockStmt).getStmt(10)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(10).getFollowingStmt()=target_0))
}

predicate func_1(Variable vconn_opt_64, ExprStmt target_5, PostfixIncrExpr target_6, LogicalAndExpr target_3) {
	exists(LogicalAndExpr target_1 |
		target_1.getAnOperand() instanceof LogicalAndExpr
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("strcmp")
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="keyword"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_opt_64
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="dbname"
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getParent().(IfStmt).getThen()=target_5
		and target_6.getOperand().(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Variable vconn_opt_64, BlockStmt target_7, PostfixIncrExpr target_8, LogicalAndExpr target_4) {
	exists(LogicalAndExpr target_2 |
		target_2.getAnOperand() instanceof LogicalAndExpr
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("strcmp")
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="keyword"
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_opt_64
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="dbname"
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_2.getParent().(IfStmt).getThen()=target_7
		and target_8.getOperand().(VariableAccess).getLocation().isBefore(target_2.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_2.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_3(Variable vconn_opt_64, ExprStmt target_5, LogicalAndExpr target_3) {
		target_3.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="val"
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_opt_64
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="val"
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_opt_64
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_3.getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="0"
		and target_3.getParent().(IfStmt).getThen()=target_5
}

predicate func_4(Variable vconn_opt_64, BlockStmt target_7, LogicalAndExpr target_4) {
		target_4.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="val"
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_opt_64
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="val"
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_opt_64
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="0"
		and target_4.getParent().(IfStmt).getThen()=target_7
}

predicate func_5(ExprStmt target_5) {
		target_5.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget().getType().hasName("int")
}

predicate func_6(Variable vconn_opt_64, PostfixIncrExpr target_6) {
		target_6.getOperand().(VariableAccess).getTarget()=vconn_opt_64
}

predicate func_7(Variable vconn_opt_64, BlockStmt target_7) {
		target_7.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget().getType().hasName("const char **")
		and target_7.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget().getType().hasName("int")
		and target_7.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="keyword"
		and target_7.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_opt_64
		and target_7.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget().getType().hasName("const char **")
		and target_7.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget().getType().hasName("int")
		and target_7.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="val"
		and target_7.getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vconn_opt_64
}

predicate func_8(Variable vconn_opt_64, PostfixIncrExpr target_8) {
		target_8.getOperand().(VariableAccess).getTarget()=vconn_opt_64
}

from Function func, Variable vconn_opt_64, LogicalAndExpr target_3, LogicalAndExpr target_4, ExprStmt target_5, PostfixIncrExpr target_6, BlockStmt target_7, PostfixIncrExpr target_8
where
not func_0(func)
and not func_1(vconn_opt_64, target_5, target_6, target_3)
and not func_2(vconn_opt_64, target_7, target_8, target_4)
and func_3(vconn_opt_64, target_5, target_3)
and func_4(vconn_opt_64, target_7, target_4)
and func_5(target_5)
and func_6(vconn_opt_64, target_6)
and func_7(vconn_opt_64, target_7)
and func_8(vconn_opt_64, target_8)
and vconn_opt_64.getType().hasName("PQconninfoOption *")
and vconn_opt_64.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
