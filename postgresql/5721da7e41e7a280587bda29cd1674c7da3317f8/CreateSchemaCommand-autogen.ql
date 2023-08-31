/**
 * @name postgresql-5721da7e41e7a280587bda29cd1674c7da3317f8-CreateSchemaCommand
 * @id cpp/postgresql/5721da7e41e7a280587bda29cd1674c7da3317f8/CreateSchemaCommand
 * @description postgresql-5721da7e41e7a280587bda29cd1674c7da3317f8-src/backend/commands/schemacmds.c-CreateSchemaCommand CVE-2022-2625
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vschemaName_53, Variable vnamespaceId_54, LogicalAndExpr target_8, ExprStmt target_9, ExprStmt target_10) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vnamespaceId_54
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("get_namespace_oid")
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vschemaName_53
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_8
		and target_9.getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_10.getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_1(Variable vnamespaceId_54, Variable vaddress_62, LogicalAndExpr target_8, ExprStmt target_12) {
	exists(IfStmt target_1 |
		target_1.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vnamespaceId_54
		and target_1.getCondition().(EqualityOperation).getAnOperand() instanceof Literal
		and target_1.getThen().(BlockStmt).getStmt(0).(DoStmt).getCondition() instanceof Literal
		and target_1.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="classId"
		and target_1.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="2615"
		and target_1.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="objectId"
		and target_1.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vnamespaceId_54
		and target_1.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="objectSubId"
		and target_1.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue() instanceof Literal
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("checkMembershipInCurrentExtension")
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vaddress_62
		and target_1.getThen().(BlockStmt).getStmt(2).(DoStmt).getCondition() instanceof Literal
		and target_1.getThen().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(ConditionalExpr).getThen().(FunctionCall).getTarget().hasName("errstart_cold")
		and target_1.getThen().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(ConditionalExpr).getElse().(FunctionCall).getTarget().hasName("errstart")
		and target_1.getThen().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(LogicalAndExpr).getValue()="0"
		and target_1.getThen().(BlockStmt).getStmt(2).(DoStmt).getStmt().(BlockStmt).getStmt(2).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__builtin_unreachable")
		and target_1.getThen().(BlockStmt).getStmt(3) instanceof ReturnStmt
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_8
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getLocation().isBefore(target_12.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(LogicalAndExpr target_8, Function func, ReturnStmt target_2) {
		target_2.getExpr().(Literal).getValue()="0"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_8
		and target_2.getEnclosingFunction() = func
}

predicate func_3(Parameter vstmt_50, BlockStmt target_13, PointerFieldAccess target_3) {
		target_3.getTarget().getName()="if_not_exists"
		and target_3.getQualifier().(VariableAccess).getTarget()=vstmt_50
		and target_3.getParent().(LogicalAndExpr).getAnOperand() instanceof FunctionCall
		and target_3.getParent().(LogicalAndExpr).getParent().(IfStmt).getThen()=target_13
}

predicate func_4(Variable vschemaName_53, VariableAccess target_4) {
		target_4.getTarget()=vschemaName_53
		and target_4.getParent().(FunctionCall).getParent().(LogicalAndExpr).getAnOperand() instanceof FunctionCall
}

predicate func_8(Variable vschemaName_53, Parameter vstmt_50, BlockStmt target_13, LogicalAndExpr target_8) {
		target_8.getAnOperand().(PointerFieldAccess).getTarget().getName()="if_not_exists"
		and target_8.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstmt_50
		and target_8.getAnOperand().(FunctionCall).getTarget().hasName("SearchSysCacheExists")
		and target_8.getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vschemaName_53
		and target_8.getAnOperand().(FunctionCall).getArgument(2) instanceof Literal
		and target_8.getAnOperand().(FunctionCall).getArgument(3) instanceof Literal
		and target_8.getAnOperand().(FunctionCall).getArgument(4) instanceof Literal
		and target_8.getParent().(IfStmt).getThen()=target_13
}

predicate func_9(Variable vschemaName_53, ExprStmt target_9) {
		target_9.getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getLeftOperand().(CommaExpr).getLeftOperand().(FunctionCall).getTarget().hasName("errcode")
		and target_9.getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getLeftOperand().(CommaExpr).getLeftOperand().(FunctionCall).getArgument(0).(AddExpr).getValue()="151818372"
		and target_9.getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(FunctionCall).getTarget().hasName("errmsg")
		and target_9.getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(FunctionCall).getArgument(0).(StringLiteral).getValue()="unacceptable schema name \"%s\""
		and target_9.getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vschemaName_53
		and target_9.getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(FunctionCall).getTarget().hasName("errdetail")
		and target_9.getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(FunctionCall).getArgument(0).(StringLiteral).getValue()="The prefix \"pg_\" is reserved for system schemas."
		and target_9.getExpr().(CommaExpr).getRightOperand().(FunctionCall).getTarget().hasName("errfinish")
		and target_9.getExpr().(CommaExpr).getRightOperand().(FunctionCall).getArgument(0) instanceof StringLiteral
		and target_9.getExpr().(CommaExpr).getRightOperand().(FunctionCall).getArgument(1) instanceof Literal
		and target_9.getExpr().(CommaExpr).getRightOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType() instanceof ArrayType
}

predicate func_10(Variable vschemaName_53, ExprStmt target_10) {
		target_10.getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getLeftOperand().(FunctionCall).getTarget().hasName("errcode")
		and target_10.getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getLeftOperand().(FunctionCall).getArgument(0).(AddExpr).getValue()="100794500"
		and target_10.getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(FunctionCall).getTarget().hasName("errmsg")
		and target_10.getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(FunctionCall).getArgument(0).(StringLiteral).getValue()="schema \"%s\" already exists, skipping"
		and target_10.getExpr().(CommaExpr).getLeftOperand().(CommaExpr).getRightOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vschemaName_53
		and target_10.getExpr().(CommaExpr).getRightOperand().(FunctionCall).getTarget().hasName("errfinish")
		and target_10.getExpr().(CommaExpr).getRightOperand().(FunctionCall).getArgument(0) instanceof StringLiteral
		and target_10.getExpr().(CommaExpr).getRightOperand().(FunctionCall).getArgument(1) instanceof Literal
		and target_10.getExpr().(CommaExpr).getRightOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget().getType() instanceof ArrayType
}

predicate func_12(Variable vaddress_62, ExprStmt target_12) {
		target_12.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="classId"
		and target_12.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vaddress_62
		and target_12.getExpr().(AssignExpr).getRValue().(Literal).getValue()="2615"
}

predicate func_13(BlockStmt target_13) {
		target_13.getStmt(0).(DoStmt).getCondition() instanceof Literal
		and target_13.getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(ConditionalExpr).getCondition().(LogicalAndExpr).getValue()="0"
		and target_13.getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(ConditionalExpr).getThen().(FunctionCall).getTarget().hasName("errstart_cold")
		and target_13.getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(ConditionalExpr).getThen().(FunctionCall).getArgument(0).(Literal).getValue()="18"
		and target_13.getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(ConditionalExpr).getThen().(FunctionCall).getArgument(1) instanceof Literal
		and target_13.getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(ConditionalExpr).getElse().(FunctionCall).getTarget().hasName("errstart")
		and target_13.getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(ConditionalExpr).getElse().(FunctionCall).getArgument(0).(Literal).getValue()="18"
		and target_13.getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(ConditionalExpr).getElse().(FunctionCall).getArgument(1) instanceof Literal
		and target_13.getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(CommaExpr).getRightOperand().(FunctionCall).getTarget().hasName("errfinish")
}

from Function func, Variable vschemaName_53, Variable vnamespaceId_54, Parameter vstmt_50, Variable vaddress_62, ReturnStmt target_2, PointerFieldAccess target_3, VariableAccess target_4, LogicalAndExpr target_8, ExprStmt target_9, ExprStmt target_10, ExprStmt target_12, BlockStmt target_13
where
not func_0(vschemaName_53, vnamespaceId_54, target_8, target_9, target_10)
and not func_1(vnamespaceId_54, vaddress_62, target_8, target_12)
and func_2(target_8, func, target_2)
and func_3(vstmt_50, target_13, target_3)
and func_4(vschemaName_53, target_4)
and func_8(vschemaName_53, vstmt_50, target_13, target_8)
and func_9(vschemaName_53, target_9)
and func_10(vschemaName_53, target_10)
and func_12(vaddress_62, target_12)
and func_13(target_13)
and vschemaName_53.getType().hasName("const char *")
and vnamespaceId_54.getType().hasName("Oid")
and vstmt_50.getType().hasName("CreateSchemaStmt *")
and vaddress_62.getType().hasName("ObjectAddress")
and vschemaName_53.(LocalVariable).getFunction() = func
and vnamespaceId_54.(LocalVariable).getFunction() = func
and vstmt_50.getFunction() = func
and vaddress_62.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
