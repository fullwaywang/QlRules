/**
 * @name wireshark-7e90aed666e809c0db5de9d1816802a7dcea28d9-asn1_get_real
 * @id cpp/wireshark/7e90aed666e809c0db5de9d1816802a7dcea28d9/asn1-get-real
 * @description wireshark-7e90aed666e809c0db5de9d1816802a7dcea28d9-epan/asn1.c-asn1_get_real CVE-2019-13619
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vlen_191, Variable vlenE_214, BitwiseAndExpr target_1, ExprStmt target_2, ExprStmt target_3, EqualityOperation target_4, RelationalOperation target_5) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vlenE_214
		and target_0.getExpr().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vlen_191
		and target_0.getExpr().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(SubExpr).getRightOperand() instanceof Literal
		and target_0.getExpr().(ConditionalExpr).getThen() instanceof Literal
		and target_0.getExpr().(ConditionalExpr).getElse().(FunctionCall).getTarget().hasName("proto_report_dissector_bug")
		and target_0.getExpr().(ConditionalExpr).getElse().(FunctionCall).getArgument(0).(StringLiteral).getValue()="%s:%u: failed assertion \"%s\""
		and target_0.getExpr().(ConditionalExpr).getElse().(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_0.getExpr().(ConditionalExpr).getElse().(FunctionCall).getArgument(2) instanceof Literal
		and target_0.getExpr().(ConditionalExpr).getElse().(FunctionCall).getArgument(3).(StringLiteral).getValue()="lenE < len - 1"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(13)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1
		and target_2.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getExpr().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(SubExpr).getLeftOperand().(VariableAccess).getLocation())
		and target_0.getExpr().(ConditionalExpr).getCondition().(RelationalOperation).getGreaterOperand().(SubExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(VariableAccess).getLocation())
		and target_4.getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getExpr().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation())
		and target_0.getExpr().(ConditionalExpr).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_5.getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_1(BitwiseAndExpr target_1) {
		target_1.getRightOperand().(HexLiteral).getValue()="128"
}

predicate func_2(Parameter vlen_191, ExprStmt target_2) {
		target_2.getExpr().(AssignSubExpr).getLValue().(VariableAccess).getTarget()=vlen_191
		and target_2.getExpr().(AssignSubExpr).getRValue().(Literal).getValue()="1"
}

predicate func_3(Parameter vlen_191, Variable vlenE_214, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vlen_191
		and target_3.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vlenE_214
}

predicate func_4(Variable vlenE_214, EqualityOperation target_4) {
		target_4.getAnOperand().(VariableAccess).getTarget()=vlenE_214
		and target_4.getAnOperand().(Literal).getValue()="4"
}

predicate func_5(Variable vlenE_214, RelationalOperation target_5) {
		 (target_5 instanceof GTExpr or target_5 instanceof LTExpr)
		and target_5.getGreaterOperand().(VariableAccess).getTarget()=vlenE_214
}

from Function func, Parameter vlen_191, Variable vlenE_214, BitwiseAndExpr target_1, ExprStmt target_2, ExprStmt target_3, EqualityOperation target_4, RelationalOperation target_5
where
not func_0(vlen_191, vlenE_214, target_1, target_2, target_3, target_4, target_5)
and func_1(target_1)
and func_2(vlen_191, target_2)
and func_3(vlen_191, vlenE_214, target_3)
and func_4(vlenE_214, target_4)
and func_5(vlenE_214, target_5)
and vlen_191.getType().hasName("gint")
and vlenE_214.getType().hasName("guint8")
and vlen_191.getParentScope+() = func
and vlenE_214.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
