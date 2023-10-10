/**
 * @name neomutt-3c49c44be9b459d9c616bcaef6eb5d51298c1741-cmd_parse_status
 * @id cpp/neomutt/3c49c44be9b459d9c616bcaef6eb5d51298c1741/cmd-parse-status
 * @description neomutt-3c49c44be9b459d9c616bcaef6eb5d51298c1741-imap/command.c-cmd_parse_status CVE-2018-14351
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vidata_617, Variable vlitlen_624, EqualityOperation target_1, ExprStmt target_2, ExprStmt target_3, AddressOfExpr target_4, ExprStmt target_5) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getTarget().hasName("strlen")
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="buf"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vidata_617
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlitlen_624
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getExpr().(VariableAccess).getType().hasName("log_dispatcher_t")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(0) instanceof Literal
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(1) instanceof StringLiteral
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(2) instanceof Literal
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(3).(VariableAccess).getType().hasName("const char[17]")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(4) instanceof Literal
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(VariableCall).getArgument(5).(StringLiteral).getValue()="Error parsing STATUS mailbox\n"
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).toString() = "return ..."
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_4.getOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_5.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vlitlen_624, EqualityOperation target_1) {
		target_1.getAnOperand().(FunctionCall).getTarget().hasName("imap_get_literal_count")
		and target_1.getAnOperand().(FunctionCall).getArgument(1).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vlitlen_624
		and target_1.getAnOperand().(Literal).getValue()="0"
}

predicate func_2(Parameter vidata_617, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="status"
		and target_2.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vidata_617
}

predicate func_3(Parameter vidata_617, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="buf"
		and target_3.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vidata_617
}

predicate func_4(Variable vlitlen_624, AddressOfExpr target_4) {
		target_4.getOperand().(VariableAccess).getTarget()=vlitlen_624
}

predicate func_5(Variable vlitlen_624, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vlitlen_624
}

from Function func, Parameter vidata_617, Variable vlitlen_624, EqualityOperation target_1, ExprStmt target_2, ExprStmt target_3, AddressOfExpr target_4, ExprStmt target_5
where
not func_0(vidata_617, vlitlen_624, target_1, target_2, target_3, target_4, target_5)
and func_1(vlitlen_624, target_1)
and func_2(vidata_617, target_2)
and func_3(vidata_617, target_3)
and func_4(vlitlen_624, target_4)
and func_5(vlitlen_624, target_5)
and vidata_617.getType().hasName("ImapData *")
and vlitlen_624.getType().hasName("unsigned int")
and vidata_617.getParentScope+() = func
and vlitlen_624.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
