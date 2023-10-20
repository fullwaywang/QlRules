/**
 * @name libxml2-c1d1f7121194036608bf555f08d3062a36fd344b-xmlXPtrNewRange
 * @id cpp/libxml2/c1d1f7121194036608bf555f08d3062a36fd344b/xmlXPtrNewRange
 * @description libxml2-c1d1f7121194036608bf555f08d3062a36fd344b-xpointer.c-xmlXPtrNewRange CVE-2016-4658
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vstart_334, Parameter vstartindex_334, Parameter vend_335, Parameter vendindex_335, Variable vret_336, EqualityOperation target_15, RelationalOperation target_16, EqualityOperation target_17, RelationalOperation target_18) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("xmlXPtrNewRangeInternal")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vstart_334
		and target_0.getArgument(1).(VariableAccess).getTarget()=vstartindex_334
		and target_0.getArgument(2).(VariableAccess).getTarget()=vend_335
		and target_0.getArgument(3).(VariableAccess).getTarget()=vendindex_335
		and target_0.getParent().(AssignExpr).getRValue() = target_0
		and target_0.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_336
		and target_15.getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getArgument(0).(VariableAccess).getLocation())
		and target_16.getLesserOperand().(VariableAccess).getLocation().isBefore(target_0.getArgument(1).(VariableAccess).getLocation())
		and target_17.getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getArgument(2).(VariableAccess).getLocation())
		and target_18.getLesserOperand().(VariableAccess).getLocation().isBefore(target_0.getArgument(3).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vstart_334, Variable vret_336, VariableAccess target_1) {
		target_1.getTarget()=vstart_334
		and target_1.getParent().(AssignExpr).getRValue() = target_1
		and target_1.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="user"
		and target_1.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_336
}

predicate func_2(Parameter vstartindex_334, Variable vret_336, VariableAccess target_2) {
		target_2.getTarget()=vstartindex_334
		and target_2.getParent().(AssignExpr).getRValue() = target_2
		and target_2.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="index"
		and target_2.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_336
}

predicate func_3(Parameter vend_335, Variable vret_336, VariableAccess target_3) {
		target_3.getTarget()=vend_335
		and target_3.getParent().(AssignExpr).getRValue() = target_3
		and target_3.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="user2"
		and target_3.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_336
}

predicate func_4(Parameter vendindex_335, Variable vret_336, VariableAccess target_4) {
		target_4.getTarget()=vendindex_335
		and target_4.getParent().(AssignExpr).getRValue() = target_4
		and target_4.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="index2"
		and target_4.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_336
}

predicate func_5(Variable vxmlMalloc, VariableCall target_5) {
		target_5.getExpr().(VariableAccess).getTarget()=vxmlMalloc
		and target_5.getArgument(0).(SizeofTypeOperator).getType() instanceof LongType
		and target_5.getArgument(0).(SizeofTypeOperator).getValue()="72"
}

predicate func_6(Variable vret_336, Function func, IfStmt target_6) {
		target_6.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vret_336
		and target_6.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("xmlXPtrErrMemory")
		and target_6.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="allocating range"
		and target_6.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_6
}

/*predicate func_7(EqualityOperation target_19, Function func, ExprStmt target_7) {
		target_7.getExpr().(FunctionCall).getTarget().hasName("xmlXPtrErrMemory")
		and target_7.getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="allocating range"
		and target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_19
		and target_7.getEnclosingFunction() = func
}

*/
/*predicate func_8(EqualityOperation target_19, Function func, ReturnStmt target_8) {
		target_8.getExpr().(Literal).getValue()="0"
		and target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_19
		and target_8.getEnclosingFunction() = func
}

*/
predicate func_9(Variable vret_336, Function func, ExprStmt target_9) {
		target_9.getExpr().(FunctionCall).getTarget().hasName("memset")
		and target_9.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vret_336
		and target_9.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="0"
		and target_9.getExpr().(FunctionCall).getArgument(2).(SizeofTypeOperator).getType() instanceof LongType
		and target_9.getExpr().(FunctionCall).getArgument(2).(SizeofTypeOperator).getValue()="72"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_9
}

predicate func_10(Variable vret_336, Function func, ExprStmt target_10) {
		target_10.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="type"
		and target_10.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_336
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_10
}

predicate func_11(Parameter vstart_334, Variable vret_336, Function func, ExprStmt target_11) {
		target_11.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="user"
		and target_11.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_336
		and target_11.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vstart_334
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_11
}

predicate func_12(Parameter vstartindex_334, Variable vret_336, Function func, ExprStmt target_12) {
		target_12.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="index"
		and target_12.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_336
		and target_12.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vstartindex_334
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_12
}

predicate func_13(Parameter vend_335, Variable vret_336, Function func, ExprStmt target_13) {
		target_13.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="user2"
		and target_13.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_336
		and target_13.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vend_335
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_13
}

predicate func_14(Parameter vendindex_335, Variable vret_336, Function func, ExprStmt target_14) {
		target_14.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="index2"
		and target_14.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_336
		and target_14.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vendindex_335
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_14
}

predicate func_15(Parameter vstart_334, EqualityOperation target_15) {
		target_15.getAnOperand().(VariableAccess).getTarget()=vstart_334
		and target_15.getAnOperand().(Literal).getValue()="0"
}

predicate func_16(Parameter vstartindex_334, RelationalOperation target_16) {
		 (target_16 instanceof GTExpr or target_16 instanceof LTExpr)
		and target_16.getLesserOperand().(VariableAccess).getTarget()=vstartindex_334
		and target_16.getGreaterOperand().(Literal).getValue()="0"
}

predicate func_17(Parameter vend_335, EqualityOperation target_17) {
		target_17.getAnOperand().(VariableAccess).getTarget()=vend_335
		and target_17.getAnOperand().(Literal).getValue()="0"
}

predicate func_18(Parameter vendindex_335, RelationalOperation target_18) {
		 (target_18 instanceof GTExpr or target_18 instanceof LTExpr)
		and target_18.getLesserOperand().(VariableAccess).getTarget()=vendindex_335
		and target_18.getGreaterOperand().(Literal).getValue()="0"
}

predicate func_19(Variable vret_336, EqualityOperation target_19) {
		target_19.getAnOperand().(VariableAccess).getTarget()=vret_336
		and target_19.getAnOperand() instanceof Literal
}

from Function func, Parameter vstart_334, Parameter vstartindex_334, Parameter vend_335, Parameter vendindex_335, Variable vret_336, Variable vxmlMalloc, VariableAccess target_1, VariableAccess target_2, VariableAccess target_3, VariableAccess target_4, VariableCall target_5, IfStmt target_6, ExprStmt target_9, ExprStmt target_10, ExprStmt target_11, ExprStmt target_12, ExprStmt target_13, ExprStmt target_14, EqualityOperation target_15, RelationalOperation target_16, EqualityOperation target_17, RelationalOperation target_18, EqualityOperation target_19
where
not func_0(vstart_334, vstartindex_334, vend_335, vendindex_335, vret_336, target_15, target_16, target_17, target_18)
and func_1(vstart_334, vret_336, target_1)
and func_2(vstartindex_334, vret_336, target_2)
and func_3(vend_335, vret_336, target_3)
and func_4(vendindex_335, vret_336, target_4)
and func_5(vxmlMalloc, target_5)
and func_6(vret_336, func, target_6)
and func_9(vret_336, func, target_9)
and func_10(vret_336, func, target_10)
and func_11(vstart_334, vret_336, func, target_11)
and func_12(vstartindex_334, vret_336, func, target_12)
and func_13(vend_335, vret_336, func, target_13)
and func_14(vendindex_335, vret_336, func, target_14)
and func_15(vstart_334, target_15)
and func_16(vstartindex_334, target_16)
and func_17(vend_335, target_17)
and func_18(vendindex_335, target_18)
and func_19(vret_336, target_19)
and vstart_334.getType().hasName("xmlNodePtr")
and vstartindex_334.getType().hasName("int")
and vend_335.getType().hasName("xmlNodePtr")
and vendindex_335.getType().hasName("int")
and vret_336.getType().hasName("xmlXPathObjectPtr")
and vxmlMalloc.getType().hasName("xmlMallocFunc")
and vstart_334.getFunction() = func
and vstartindex_334.getFunction() = func
and vend_335.getFunction() = func
and vendindex_335.getFunction() = func
and vret_336.(LocalVariable).getFunction() = func
and not vxmlMalloc.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
