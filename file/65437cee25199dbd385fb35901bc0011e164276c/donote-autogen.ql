/**
 * @name file-65437cee25199dbd385fb35901bc0011e164276c-donote
 * @id cpp/file/65437cee25199dbd385fb35901bc0011e164276c/donote
 * @description file-65437cee25199dbd385fb35901bc0011e164276c-src/readelf.c-donote CVE-2014-9621
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vdescsz_822, LogicalAndExpr target_4, FunctionCall target_5, EqualityOperation target_6) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vdescsz_822
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="100"
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vdescsz_822
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="100"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
		and target_5.getArgument(5).(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_6.getAnOperand().(FunctionCall).getArgument(2).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vflags_817, ConditionalExpr target_7, BitwiseAndExpr target_8, BitwiseAndExpr target_9) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignOrExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vflags_817
		and target_1.getExpr().(AssignOrExpr).getRValue().(Literal).getValue()="32"
		and target_1.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_7
		and target_8.getLeftOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_1.getExpr().(AssignOrExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation())
		and target_1.getExpr().(AssignOrExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_9.getLeftOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_2(Parameter vflags_817, ConditionalExpr target_7, BitwiseAndExpr target_9, BitwiseAndExpr target_10) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignOrExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vflags_817
		and target_2.getExpr().(AssignOrExpr).getRValue().(Literal).getValue()="64"
		and target_2.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_7
		and target_9.getLeftOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignOrExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation())
		and target_2.getExpr().(AssignOrExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_10.getLeftOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_3(Parameter vflags_817, ConditionalExpr target_7, BitwiseAndExpr target_10) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(AssignOrExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vflags_817
		and target_3.getExpr().(AssignOrExpr).getRValue().(Literal).getValue()="128"
		and target_3.getParent().(BlockStmt).getParent().(SwitchStmt).getExpr()=target_7
		and target_10.getLeftOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignOrExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_4(LogicalAndExpr target_4) {
		target_4.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="7"
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getTarget().hasName("strcmp")
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="NetBSD"
		and target_4.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
}

predicate func_5(Parameter vflags_817, Variable vdescsz_822, FunctionCall target_5) {
		target_5.getTarget().hasName("do_core_note")
		and target_5.getArgument(2).(ConditionalExpr).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_5.getArgument(2).(ConditionalExpr).getThen().(FunctionCall).getTarget().hasName("getu32")
		and target_5.getArgument(2).(ConditionalExpr).getThen().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="n_type"
		and target_5.getArgument(2).(ConditionalExpr).getElse().(FunctionCall).getTarget().hasName("getu32")
		and target_5.getArgument(2).(ConditionalExpr).getElse().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="n_type"
		and target_5.getArgument(5).(VariableAccess).getTarget()=vdescsz_822
		and target_5.getArgument(8).(VariableAccess).getTarget()=vflags_817
}

predicate func_6(Variable vdescsz_822, EqualityOperation target_6) {
		target_6.getAnOperand().(FunctionCall).getTarget().hasName("file_printf")
		and target_6.getAnOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()=", compiled for: %.*s"
		and target_6.getAnOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vdescsz_822
		and target_6.getAnOperand().(UnaryMinusExpr).getValue()="-1"
}

predicate func_7(ConditionalExpr target_7) {
		target_7.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="1"
		and target_7.getThen().(FunctionCall).getTarget().hasName("getu32")
		and target_7.getThen().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="n_type"
		and target_7.getElse().(FunctionCall).getTarget().hasName("getu32")
		and target_7.getElse().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="n_type"
}

predicate func_8(Parameter vflags_817, BitwiseAndExpr target_8) {
		target_8.getLeftOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vflags_817
		and target_8.getRightOperand().(Literal).getValue()="32"
}

predicate func_9(Parameter vflags_817, BitwiseAndExpr target_9) {
		target_9.getLeftOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vflags_817
		and target_9.getRightOperand().(Literal).getValue()="64"
}

predicate func_10(Parameter vflags_817, BitwiseAndExpr target_10) {
		target_10.getLeftOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vflags_817
		and target_10.getRightOperand().(Literal).getValue()="128"
}

from Function func, Parameter vflags_817, Variable vdescsz_822, LogicalAndExpr target_4, FunctionCall target_5, EqualityOperation target_6, ConditionalExpr target_7, BitwiseAndExpr target_8, BitwiseAndExpr target_9, BitwiseAndExpr target_10
where
not func_0(vdescsz_822, target_4, target_5, target_6)
and not func_1(vflags_817, target_7, target_8, target_9)
and not func_2(vflags_817, target_7, target_9, target_10)
and not func_3(vflags_817, target_7, target_10)
and func_4(target_4)
and func_5(vflags_817, vdescsz_822, target_5)
and func_6(vdescsz_822, target_6)
and func_7(target_7)
and func_8(vflags_817, target_8)
and func_9(vflags_817, target_9)
and func_10(vflags_817, target_10)
and vflags_817.getType().hasName("int *")
and vdescsz_822.getType().hasName("uint32_t")
and vflags_817.getParentScope+() = func
and vdescsz_822.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
