/**
 * @name neomutt-fb013ec666759cb8a9e294347c7b4c1f597639cc-imap_exec
 * @id cpp/neomutt/fb013ec666759cb8a9e294347c7b4c1f597639cc/imap-exec
 * @description neomutt-fb013ec666759cb8a9e294347c7b4c1f597639cc-imap/command.c-imap_exec CVE-2020-14954
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vadata_1249, Parameter vflags_1249, ExprStmt target_3, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vflags_1249
		and target_0.getCondition().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getValue()="8"
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="nextcmd"
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vadata_1249
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="lastcmd"
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vadata_1249
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("imap_exec")
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vadata_1249
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(BinaryBitwiseOperation).getValue()="4"
		and (func.getEntryPoint().(BlockStmt).getStmt(1)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(1).getFollowingStmt()=target_0)
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vadata_1249, Parameter vflags_1249, ExprStmt target_4, EqualityOperation target_5, LogicalAndExpr target_6) {
	exists(IfStmt target_1 |
		target_1.getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vflags_1249
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getValue()="8"
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="nextcmd"
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vadata_1249
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="lastcmd"
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vadata_1249
		and target_1.getThen().(BreakStmt).toString() = "break;"
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_1.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_6.getAnOperand().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_1.getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getLocation()))
}

predicate func_2(Function func) {
	exists(LabelStmt target_2 |
		target_2.toString() = "label ...:"
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Parameter vadata_1249, Parameter vflags_1249, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("cmd_start")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vadata_1249
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vflags_1249
}

predicate func_4(Parameter vadata_1249, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("imap_cmd_step")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vadata_1249
}

predicate func_5(Parameter vadata_1249, EqualityOperation target_5) {
		target_5.getAnOperand().(PointerFieldAccess).getTarget().getName()="status"
		and target_5.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vadata_1249
}

predicate func_6(Parameter vadata_1249, Parameter vflags_1249, LogicalAndExpr target_6) {
		target_6.getAnOperand().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vflags_1249
		and target_6.getAnOperand().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getValue()="4"
		and target_6.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("mutt_socket_poll")
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="conn"
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vadata_1249
		and target_6.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
}

from Function func, Parameter vadata_1249, Parameter vflags_1249, ExprStmt target_3, ExprStmt target_4, EqualityOperation target_5, LogicalAndExpr target_6
where
not func_0(vadata_1249, vflags_1249, target_3, func)
and not func_1(vadata_1249, vflags_1249, target_4, target_5, target_6)
and not func_2(func)
and func_3(vadata_1249, vflags_1249, target_3)
and func_4(vadata_1249, target_4)
and func_5(vadata_1249, target_5)
and func_6(vadata_1249, vflags_1249, target_6)
and vadata_1249.getType().hasName("ImapAccountData *")
and vflags_1249.getType().hasName("ImapCmdFlags")
and vadata_1249.getParentScope+() = func
and vflags_1249.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
