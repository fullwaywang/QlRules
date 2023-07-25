/**
 * @name libxml2-23f05e0c33987d6605387b300c4be5da2120a7ab-xmlParserEntityCheck
 * @id cpp/libxml2/23f05e0c33987d6605387b300c4be5da2120a7ab/xmlParserEntityCheck
 * @description libxml2-23f05e0c33987d6605387b300c4be5da2120a7ab-parser.c-xmlParserEntityCheck CVE-2013-0338
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vctxt_124, Variable vconsumed_127, EqualityOperation target_2, EqualityOperation target_3, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getType().hasName("size_t")
		and target_0.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("size_t")
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="10000000"
		and target_0.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="input"
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_124
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vconsumed_127
		and target_0.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vconsumed_127
		and target_0.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(PointerFieldAccess).getTarget().getName()="sizeentities"
		and target_0.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_124
		and target_0.getThen().(BlockStmt).getStmt(3).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("size_t")
		and target_0.getThen().(BlockStmt).getStmt(3).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(MulExpr).getLeftOperand().(Literal).getValue()="10"
		and target_0.getThen().(BlockStmt).getStmt(3).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vconsumed_127
		and target_0.getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_0.getElse() instanceof IfStmt
		and (func.getEntryPoint().(BlockStmt).getStmt(3)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(3).getFollowingStmt()=target_0)
		and target_2.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vctxt_124, Parameter vsize_124, Parameter vent_125, Variable vconsumed_127, Function func, IfStmt target_1) {
		target_1.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vsize_124
		and target_1.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vsize_124
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="1000"
		and target_1.getThen().(BlockStmt).getStmt(0).(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="input"
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_124
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getThen().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vconsumed_127
		and target_1.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vconsumed_127
		and target_1.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(PointerFieldAccess).getTarget().getName()="sizeentities"
		and target_1.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_124
		and target_1.getThen().(BlockStmt).getStmt(3).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vsize_124
		and target_1.getThen().(BlockStmt).getStmt(3).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(MulExpr).getLeftOperand().(Literal).getValue()="10"
		and target_1.getThen().(BlockStmt).getStmt(3).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vconsumed_127
		and target_1.getThen().(BlockStmt).getStmt(3).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(MulExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="nbentities"
		and target_1.getThen().(BlockStmt).getStmt(3).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(MulExpr).getRightOperand().(Literal).getValue()="3"
		and target_1.getThen().(BlockStmt).getStmt(3).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(MulExpr).getLeftOperand().(Literal).getValue()="10"
		and target_1.getThen().(BlockStmt).getStmt(3).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vconsumed_127
		and target_1.getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_1.getElse().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vent_125
		and target_1.getElse().(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsize_124
		and target_1.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="checked"
		and target_1.getElse().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vent_125
		and target_1.getElse().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="input"
		and target_1.getElse().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_124
		and target_1.getElse().(IfStmt).getThen().(BlockStmt).getStmt(1).(IfStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getElse().(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vconsumed_127
		and target_1.getElse().(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(PointerFieldAccess).getTarget().getName()="sizeentities"
		and target_1.getElse().(IfStmt).getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignAddExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_124
		and target_1.getElse().(IfStmt).getThen().(BlockStmt).getStmt(3).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vsize_124
		and target_1.getElse().(IfStmt).getThen().(BlockStmt).getStmt(3).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(MulExpr).getRightOperand().(Literal).getValue()="3"
		and target_1.getElse().(IfStmt).getThen().(BlockStmt).getStmt(3).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vconsumed_127
		and target_1.getElse().(IfStmt).getThen().(BlockStmt).getStmt(3).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(MulExpr).getRightOperand().(Literal).getValue()="10"
		and target_1.getElse().(IfStmt).getThen().(BlockStmt).getStmt(3).(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_1.getElse().(IfStmt).getElse().(BlockStmt).getStmt(0).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_1
}

predicate func_2(Parameter vctxt_124, EqualityOperation target_2) {
		target_2.getAnOperand().(ValueFieldAccess).getTarget().getName()="code"
		and target_2.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="lastError"
		and target_2.getAnOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_124
}

predicate func_3(Parameter vctxt_124, EqualityOperation target_3) {
		target_3.getAnOperand().(PointerFieldAccess).getTarget().getName()="input"
		and target_3.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vctxt_124
		and target_3.getAnOperand().(Literal).getValue()="0"
}

from Function func, Parameter vctxt_124, Parameter vsize_124, Parameter vent_125, Variable vconsumed_127, IfStmt target_1, EqualityOperation target_2, EqualityOperation target_3
where
not func_0(vctxt_124, vconsumed_127, target_2, target_3, func)
and func_1(vctxt_124, vsize_124, vent_125, vconsumed_127, func, target_1)
and func_2(vctxt_124, target_2)
and func_3(vctxt_124, target_3)
and vctxt_124.getType().hasName("xmlParserCtxtPtr")
and vsize_124.getType().hasName("size_t")
and vent_125.getType().hasName("xmlEntityPtr")
and vconsumed_127.getType().hasName("size_t")
and vctxt_124.getFunction() = func
and vsize_124.getFunction() = func
and vent_125.getFunction() = func
and vconsumed_127.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
