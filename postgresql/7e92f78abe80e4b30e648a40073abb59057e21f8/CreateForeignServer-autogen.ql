/**
 * @name postgresql-7e92f78abe80e4b30e648a40073abb59057e21f8-CreateForeignServer
 * @id cpp/postgresql/7e92f78abe80e4b30e648a40073abb59057e21f8/CreateForeignServer
 * @description postgresql-7e92f78abe80e4b30e648a40073abb59057e21f8-src/backend/commands/foreigncmds.c-CreateForeignServer CVE-2022-2625
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vstmt_866, Variable vsrvId_873, IfStmt target_11, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsrvId_873
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("get_foreign_server_oid")
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="servername"
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstmt_866
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1) instanceof Literal
		and (func.getEntryPoint().(BlockStmt).getStmt(13)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(13).getFollowingStmt()=target_0)
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_11.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_2(Variable vmyself_876, PointerFieldAccess target_13) {
	exists(DoStmt target_2 |
		target_2.getCondition().(Literal).getValue()="0"
		and target_2.getStmt().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_2.getStmt().(BlockStmt).getStmt(1) instanceof ExprStmt
		and target_2.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="objectSubId"
		and target_2.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vmyself_876
		and target_2.getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_13)
}

predicate func_3(Variable vmyself_876, PointerFieldAccess target_13) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(FunctionCall).getTarget().hasName("checkMembershipInCurrentExtension")
		and target_3.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vmyself_876
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_3
		and target_3.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_13)
}

predicate func_5(Variable vsrvId_873, Variable vmyself_876, ExprStmt target_15, ExprStmt target_8, ExprStmt target_7, Function func) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="objectId"
		and target_5.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vmyself_876
		and target_5.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vsrvId_873
		and (func.getEntryPoint().(BlockStmt).getStmt(34)=target_5 or func.getEntryPoint().(BlockStmt).getStmt(34).getFollowingStmt()=target_5)
		and target_15.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_5.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation())
		and target_5.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation().isBefore(target_8.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation())
		and target_5.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_7.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_6(Parameter vstmt_866, PointerFieldAccess target_6) {
		target_6.getTarget().getName()="servername"
		and target_6.getQualifier().(VariableAccess).getTarget()=vstmt_866
		and target_6.getParent().(FunctionCall).getParent().(NEExpr).getAnOperand() instanceof FunctionCall
}

predicate func_7(Variable vmyself_876, Function func, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="classId"
		and target_7.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vmyself_876
		and target_7.getExpr().(AssignExpr).getRValue().(Literal).getValue()="1417"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_7
}

predicate func_8(Variable vsrvId_873, Variable vmyself_876, Function func, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="objectId"
		and target_8.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vmyself_876
		and target_8.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vsrvId_873
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_8
}

predicate func_10(Parameter vstmt_866, BlockStmt target_16, FunctionCall target_10) {
		target_10.getTarget().hasName("GetForeignServerByName")
		and target_10.getArgument(0).(PointerFieldAccess).getTarget().getName()="servername"
		and target_10.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstmt_866
		and target_10.getArgument(1) instanceof Literal
		and target_10.getParent().(NEExpr).getAnOperand().(Literal).getValue()="0"
		and target_10.getParent().(NEExpr).getParent().(IfStmt).getThen()=target_16
}

predicate func_11(Parameter vstmt_866, IfStmt target_11) {
		target_11.getCondition().(PointerFieldAccess).getTarget().getName()="if_not_exists"
		and target_11.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstmt_866
		and target_11.getThen().(BlockStmt).getStmt(0).(DoStmt).getCondition() instanceof Literal
		and target_11.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("errstart")
		and target_11.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getArgument(0).(Literal).getValue()="18"
		and target_11.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getArgument(1) instanceof Literal
		and target_11.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(LogicalAndExpr).getValue()="0"
		and target_11.getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(2).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__builtin_unreachable")
		and target_11.getElse().(DoStmt).getCondition() instanceof Literal
		and target_11.getElse().(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("errstart")
		and target_11.getElse().(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getArgument(0) instanceof Literal
		and target_11.getElse().(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getArgument(1) instanceof Literal
		and target_11.getElse().(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(CommaExpr).getRightOperand().(FunctionCall).getTarget().hasName("errfinish")
		and target_11.getElse().(DoStmt).getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(LogicalAndExpr).getValue()="1"
		and target_11.getElse().(DoStmt).getStmt().(BlockStmt).getStmt(2).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__builtin_unreachable")
}

predicate func_13(Parameter vstmt_866, PointerFieldAccess target_13) {
		target_13.getTarget().getName()="if_not_exists"
		and target_13.getQualifier().(VariableAccess).getTarget()=vstmt_866
}

predicate func_15(Variable vsrvId_873, ExprStmt target_15) {
		target_15.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget().getType().hasName("Datum[8]")
		and target_15.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(SubExpr).getValue()="0"
		and target_15.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vsrvId_873
}

predicate func_16(Parameter vstmt_866, BlockStmt target_16) {
		target_16.getStmt(0).(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="if_not_exists"
		and target_16.getStmt(0).(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstmt_866
		and target_16.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(DoStmt).getCondition() instanceof Literal
		and target_16.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("errstart")
		and target_16.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("table_close")
		and target_16.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget().getType().hasName("Relation")
		and target_16.getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="3"
		and target_16.getStmt(0).(IfStmt).getElse().(DoStmt).getCondition() instanceof Literal
		and target_16.getStmt(0).(IfStmt).getElse().(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getTarget().hasName("errstart")
		and target_16.getStmt(0).(IfStmt).getElse().(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getArgument(0) instanceof Literal
		and target_16.getStmt(0).(IfStmt).getElse().(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(FunctionCall).getArgument(1) instanceof Literal
		and target_16.getStmt(0).(IfStmt).getElse().(DoStmt).getStmt().(BlockStmt).getStmt(2).(IfStmt).getCondition().(LogicalAndExpr).getValue()="1"
		and target_16.getStmt(0).(IfStmt).getElse().(DoStmt).getStmt().(BlockStmt).getStmt(2).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("__builtin_unreachable")
}

from Function func, Parameter vstmt_866, Variable vsrvId_873, Variable vmyself_876, PointerFieldAccess target_6, ExprStmt target_7, ExprStmt target_8, FunctionCall target_10, IfStmt target_11, PointerFieldAccess target_13, ExprStmt target_15, BlockStmt target_16
where
not func_0(vstmt_866, vsrvId_873, target_11, func)
and not func_2(vmyself_876, target_13)
and not func_3(vmyself_876, target_13)
and not func_5(vsrvId_873, vmyself_876, target_15, target_8, target_7, func)
and func_6(vstmt_866, target_6)
and func_7(vmyself_876, func, target_7)
and func_8(vsrvId_873, vmyself_876, func, target_8)
and func_10(vstmt_866, target_16, target_10)
and func_11(vstmt_866, target_11)
and func_13(vstmt_866, target_13)
and func_15(vsrvId_873, target_15)
and func_16(vstmt_866, target_16)
and vstmt_866.getType().hasName("CreateForeignServerStmt *")
and vsrvId_873.getType().hasName("Oid")
and vmyself_876.getType().hasName("ObjectAddress")
and vstmt_866.getFunction() = func
and vsrvId_873.(LocalVariable).getFunction() = func
and vmyself_876.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
