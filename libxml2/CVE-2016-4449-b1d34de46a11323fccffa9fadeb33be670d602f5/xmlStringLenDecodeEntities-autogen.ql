/**
 * @name libxml2-b1d34de46a11323fccffa9fadeb33be670d602f5-xmlStringLenDecodeEntities
 * @id cpp/libxml2/b1d34de46a11323fccffa9fadeb33be670d602f5/xmlStringLenDecodeEntities
 * @description libxml2-b1d34de46a11323fccffa9fadeb33be670d602f5-parser.c-xmlStringLenDecodeEntities CVE-2016-4449
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vctxt_2744, Variable vent_2753, EqualityOperation target_1, ExprStmt target_2, ExprStmt target_3) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="options"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_2744
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="options"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_2744
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="validate"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_2744
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("xmlLoadEntityContent")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_2744
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vent_2753
		and target_0.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("xmlWarningMsg")
		and target_0.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_2744
		and target_0.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="not validating will not read content for PE entity %s\n"
		and target_0.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getTarget().getName()="name"
		and target_0.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vent_2753
		and target_0.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1
		and target_2.getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Variable vent_2753, EqualityOperation target_1) {
		target_1.getAnOperand().(PointerFieldAccess).getTarget().getName()="content"
		and target_1.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vent_2753
		and target_1.getAnOperand().(Literal).getValue()="0"
}

predicate func_2(Parameter vctxt_2744, Variable vent_2753, ExprStmt target_2) {
		target_2.getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getTarget().getName()="nbentities"
		and target_2.getExpr().(AssignAddExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_2744
		and target_2.getExpr().(AssignAddExpr).getRValue().(DivExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="checked"
		and target_2.getExpr().(AssignAddExpr).getRValue().(DivExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vent_2753
		and target_2.getExpr().(AssignAddExpr).getRValue().(DivExpr).getRightOperand().(Literal).getValue()="2"
}

predicate func_3(Parameter vctxt_2744, Variable vent_2753, ExprStmt target_3) {
		target_3.getExpr().(FunctionCall).getTarget().hasName("xmlLoadEntityContent")
		and target_3.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vctxt_2744
		and target_3.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vent_2753
}

from Function func, Parameter vctxt_2744, Variable vent_2753, EqualityOperation target_1, ExprStmt target_2, ExprStmt target_3
where
not func_0(vctxt_2744, vent_2753, target_1, target_2, target_3)
and func_1(vent_2753, target_1)
and func_2(vctxt_2744, vent_2753, target_2)
and func_3(vctxt_2744, vent_2753, target_3)
and vctxt_2744.getType().hasName("xmlParserCtxtPtr")
and vent_2753.getType().hasName("xmlEntityPtr")
and vctxt_2744.getFunction() = func
and vent_2753.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
