/**
 * @name libxml2-c1d1f7121194036608bf555f08d3062a36fd344b-xmlXPtrNewRangePoints
 * @id cpp/libxml2/c1d1f7121194036608bf555f08d3062a36fd344b/xmlXPtrNewRangePoints
 * @description libxml2-c1d1f7121194036608bf555f08d3062a36fd344b-xpointer.c-xmlXPtrNewRangePoints CVE-2016-4658
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vend_372, Variable vret_373, Parameter vstart_372, EqualityOperation target_15, EqualityOperation target_16) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("xmlXPtrNewRangeInternal")
		and target_0.getArgument(0).(PointerFieldAccess).getTarget().getName()="user"
		and target_0.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstart_372
		and target_0.getArgument(1).(PointerFieldAccess).getTarget().getName()="index"
		and target_0.getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstart_372
		and target_0.getArgument(2).(PointerFieldAccess).getTarget().getName()="user"
		and target_0.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vend_372
		and target_0.getArgument(3).(PointerFieldAccess).getTarget().getName()="index"
		and target_0.getArgument(3).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vend_372
		and target_0.getParent().(AssignExpr).getRValue() = target_0
		and target_0.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_373
		and target_15.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_16.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable vret_373, Parameter vstart_372, PointerFieldAccess target_1) {
		target_1.getTarget().getName()="user"
		and target_1.getQualifier().(VariableAccess).getTarget()=vstart_372
		and target_1.getParent().(AssignExpr).getRValue() = target_1
		and target_1.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="user"
		and target_1.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_373
}

predicate func_2(Variable vret_373, Parameter vstart_372, PointerFieldAccess target_2) {
		target_2.getTarget().getName()="index"
		and target_2.getQualifier().(VariableAccess).getTarget()=vstart_372
		and target_2.getParent().(AssignExpr).getRValue() = target_2
		and target_2.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="index"
		and target_2.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_373
}

predicate func_3(Parameter vend_372, Variable vret_373, PointerFieldAccess target_3) {
		target_3.getTarget().getName()="user"
		and target_3.getQualifier().(VariableAccess).getTarget()=vend_372
		and target_3.getParent().(AssignExpr).getRValue() = target_3
		and target_3.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="user2"
		and target_3.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_373
}

predicate func_4(Parameter vend_372, Variable vret_373, PointerFieldAccess target_4) {
		target_4.getTarget().getName()="index"
		and target_4.getQualifier().(VariableAccess).getTarget()=vend_372
		and target_4.getParent().(AssignExpr).getRValue() = target_4
		and target_4.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="index2"
		and target_4.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_373
}

predicate func_5(Variable vxmlMalloc, VariableCall target_5) {
		target_5.getExpr().(VariableAccess).getTarget()=vxmlMalloc
		and target_5.getArgument(0).(SizeofTypeOperator).getType() instanceof LongType
		and target_5.getArgument(0).(SizeofTypeOperator).getValue()="72"
}

predicate func_6(Variable vret_373, Function func, IfStmt target_6) {
		target_6.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vret_373
		and target_6.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("xmlXPtrErrMemory")
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="allocating range"
		and target_6.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_6
}

/*predicate func_7(EqualityOperation target_17, Function func, ExprStmt target_7) {
		target_7.getExpr().(FunctionCall).getTarget().hasName("xmlXPtrErrMemory")
		and target_7.getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="allocating range"
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_17
		and target_7.getEnclosingFunction() = func
}

*/
/*predicate func_8(EqualityOperation target_17, Function func, ReturnStmt target_8) {
		target_8.getExpr().(Literal).getValue()="0"
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_17
		and target_8.getEnclosingFunction() = func
}

*/
predicate func_9(Variable vret_373, Function func, ExprStmt target_9) {
		target_9.getExpr().(FunctionCall).getTarget().hasName("memset")
		and target_9.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vret_373
		and target_9.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_9.getExpr().(FunctionCall).getArgument(2).(SizeofTypeOperator).getType() instanceof LongType
		and target_9.getExpr().(FunctionCall).getArgument(2).(SizeofTypeOperator).getValue()="72"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_9
}

predicate func_10(Variable vret_373, Function func, ExprStmt target_10) {
		target_10.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="type"
		and target_10.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_373
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_10
}

predicate func_11(Variable vret_373, Parameter vstart_372, Function func, ExprStmt target_11) {
		target_11.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="user"
		and target_11.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_373
		and target_11.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="user"
		and target_11.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstart_372
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_11
}

predicate func_12(Variable vret_373, Parameter vstart_372, Function func, ExprStmt target_12) {
		target_12.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="index"
		and target_12.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_373
		and target_12.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="index"
		and target_12.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstart_372
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_12
}

predicate func_13(Parameter vend_372, Variable vret_373, Function func, ExprStmt target_13) {
		target_13.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="user2"
		and target_13.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_373
		and target_13.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="user"
		and target_13.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vend_372
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_13
}

predicate func_14(Parameter vend_372, Variable vret_373, Function func, ExprStmt target_14) {
		target_14.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="index2"
		and target_14.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_373
		and target_14.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="index"
		and target_14.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vend_372
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_14
}

predicate func_15(Parameter vend_372, EqualityOperation target_15) {
		target_15.getAnOperand().(PointerFieldAccess).getTarget().getName()="type"
		and target_15.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vend_372
}

predicate func_16(Parameter vstart_372, EqualityOperation target_16) {
		target_16.getAnOperand().(PointerFieldAccess).getTarget().getName()="type"
		and target_16.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vstart_372
}

predicate func_17(Variable vret_373, EqualityOperation target_17) {
		target_17.getAnOperand().(VariableAccess).getTarget()=vret_373
		and target_17.getAnOperand() instanceof Literal
}

from Function func, Parameter vend_372, Variable vret_373, Variable vxmlMalloc, Parameter vstart_372, PointerFieldAccess target_1, PointerFieldAccess target_2, PointerFieldAccess target_3, PointerFieldAccess target_4, VariableCall target_5, IfStmt target_6, ExprStmt target_9, ExprStmt target_10, ExprStmt target_11, ExprStmt target_12, ExprStmt target_13, ExprStmt target_14, EqualityOperation target_15, EqualityOperation target_16, EqualityOperation target_17
where
not func_0(vend_372, vret_373, vstart_372, target_15, target_16)
and func_1(vret_373, vstart_372, target_1)
and func_2(vret_373, vstart_372, target_2)
and func_3(vend_372, vret_373, target_3)
and func_4(vend_372, vret_373, target_4)
and func_5(vxmlMalloc, target_5)
and func_6(vret_373, func, target_6)
and func_9(vret_373, func, target_9)
and func_10(vret_373, func, target_10)
and func_11(vret_373, vstart_372, func, target_11)
and func_12(vret_373, vstart_372, func, target_12)
and func_13(vend_372, vret_373, func, target_13)
and func_14(vend_372, vret_373, func, target_14)
and func_15(vend_372, target_15)
and func_16(vstart_372, target_16)
and func_17(vret_373, target_17)
and vend_372.getType().hasName("xmlXPathObjectPtr")
and vret_373.getType().hasName("xmlXPathObjectPtr")
and vxmlMalloc.getType().hasName("xmlMallocFunc")
and vstart_372.getType().hasName("xmlXPathObjectPtr")
and vend_372.getFunction() = func
and vret_373.(LocalVariable).getFunction() = func
and not vxmlMalloc.getParentScope+() = func
and vstart_372.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
