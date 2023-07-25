/**
 * @name neomutt-95e80bf9ff10f68cb6443f760b85df4117cb15eb-imap_subscribe
 * @id cpp/neomutt/95e80bf9ff10f68cb6443f760b85df4117cb15eb/imap-subscribe
 * @description neomutt-95e80bf9ff10f68cb6443f760b85df4117cb15eb-imap/imap.c-imap_subscribe CVE-2018-14354
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, StringLiteral target_0) {
		target_0.getValue()="%smailboxes \"%s\""
		and not target_0.getValue()="%smailboxes "
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Parameter vsubscribe_1704, Variable vmbox_1708, IfStmt target_4) {
	exists(AssignExpr target_1 |
		target_1.getLValue().(VariableAccess).getType().hasName("size_t")
		and target_1.getRValue().(FunctionCall).getTarget().hasName("snprintf")
		and target_1.getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vmbox_1708
		and target_1.getRValue().(FunctionCall).getArgument(1).(SizeofExprOperator).getValue()="1024"
		and target_1.getRValue().(FunctionCall).getArgument(2).(StringLiteral).getValue()="%smailboxes "
		and target_1.getRValue().(FunctionCall).getArgument(3).(ConditionalExpr).getCondition().(VariableAccess).getTarget()=vsubscribe_1704
		and target_1.getRValue().(FunctionCall).getArgument(3).(ConditionalExpr).getThen().(StringLiteral).getValue()=""
		and target_1.getRValue().(FunctionCall).getArgument(3).(ConditionalExpr).getElse().(StringLiteral).getValue()="un"
		and target_1.getRValue().(FunctionCall).getArgument(3).(ConditionalExpr).getCondition().(VariableAccess).getLocation().isBefore(target_4.getCondition().(VariableAccess).getLocation()))
}

predicate func_2(Variable vmbox_1708, Parameter vpath_1704, VariableAccess target_5, LogicalOrExpr target_7) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(FunctionCall).getTarget().hasName("imap_quote_string")
		and target_2.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vmbox_1708
		and target_2.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getType().hasName("size_t")
		and target_2.getExpr().(FunctionCall).getArgument(1).(SubExpr).getLeftOperand().(SizeofExprOperator).getValue()="1024"
		and target_2.getExpr().(FunctionCall).getArgument(1).(SubExpr).getRightOperand().(VariableAccess).getType().hasName("size_t")
		and target_2.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vpath_1704
		and target_2.getExpr().(FunctionCall).getArgument(3).(Literal).getValue()="1"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(5)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
		and target_7.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_2.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation()))
}

predicate func_3(Parameter vsubscribe_1704, Variable vmbox_1708, Parameter vpath_1704, VariableAccess target_3) {
		target_3.getTarget()=vpath_1704
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("snprintf")
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vmbox_1708
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(SizeofExprOperator).getValue()="1024"
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof StringLiteral
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(ConditionalExpr).getCondition().(VariableAccess).getTarget()=vsubscribe_1704
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(ConditionalExpr).getThen().(StringLiteral).getValue()=""
		and target_3.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(ConditionalExpr).getElse().(StringLiteral).getValue()="un"
}

predicate func_4(Parameter vsubscribe_1704, IfStmt target_4) {
		target_4.getCondition().(VariableAccess).getTarget()=vsubscribe_1704
		and target_4.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(0) instanceof Literal
		and target_4.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(1) instanceof StringLiteral
		and target_4.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(2) instanceof Literal
		and target_4.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(5).(FunctionCall).getTarget().hasName("dcgettext")
		and target_4.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(5).(FunctionCall).getArgument(0) instanceof Literal
		and target_4.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(5).(FunctionCall).getArgument(1).(StringLiteral).getValue()="Subscribing to %s..."
		and target_4.getThen().(ExprStmt).getExpr().(VariableCall).getArgument(5).(FunctionCall).getArgument(2) instanceof Literal
		and target_4.getElse().(ExprStmt).getExpr().(VariableCall).getArgument(0) instanceof Literal
		and target_4.getElse().(ExprStmt).getExpr().(VariableCall).getArgument(1) instanceof StringLiteral
		and target_4.getElse().(ExprStmt).getExpr().(VariableCall).getArgument(2) instanceof Literal
		and target_4.getElse().(ExprStmt).getExpr().(VariableCall).getArgument(5).(FunctionCall).getTarget().hasName("dcgettext")
		and target_4.getElse().(ExprStmt).getExpr().(VariableCall).getArgument(5).(FunctionCall).getArgument(0) instanceof Literal
		and target_4.getElse().(ExprStmt).getExpr().(VariableCall).getArgument(5).(FunctionCall).getArgument(1).(StringLiteral).getValue()="Unsubscribing from %s..."
		and target_4.getElse().(ExprStmt).getExpr().(VariableCall).getArgument(5).(FunctionCall).getArgument(2) instanceof Literal
}

predicate func_5(Variable vImapCheckSubscribed, VariableAccess target_5) {
		target_5.getTarget()=vImapCheckSubscribed
}

predicate func_7(Parameter vpath_1704, LogicalOrExpr target_7) {
		target_7.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("mx_is_imap")
		and target_7.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpath_1704
		and target_7.getAnOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getTarget().hasName("imap_parse_path")
		and target_7.getAnOperand().(LogicalOrExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpath_1704
		and target_7.getAnOperand().(NotExpr).getOperand().(ValueFieldAccess).getTarget().getName()="mbox"
}

from Function func, Parameter vsubscribe_1704, Variable vmbox_1708, Variable vImapCheckSubscribed, Parameter vpath_1704, StringLiteral target_0, VariableAccess target_3, IfStmt target_4, VariableAccess target_5, LogicalOrExpr target_7
where
func_0(func, target_0)
and not func_1(vsubscribe_1704, vmbox_1708, target_4)
and not func_2(vmbox_1708, vpath_1704, target_5, target_7)
and func_3(vsubscribe_1704, vmbox_1708, vpath_1704, target_3)
and func_4(vsubscribe_1704, target_4)
and func_5(vImapCheckSubscribed, target_5)
and func_7(vpath_1704, target_7)
and vsubscribe_1704.getType().hasName("bool")
and vmbox_1708.getType().hasName("char[1024]")
and vImapCheckSubscribed.getType().hasName("bool")
and vpath_1704.getType().hasName("char *")
and vsubscribe_1704.getParentScope+() = func
and vmbox_1708.getParentScope+() = func
and not vImapCheckSubscribed.getParentScope+() = func
and vpath_1704.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
