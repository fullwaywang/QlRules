/**
 * @name expat-be4b1c06daba1849b8ff5e00bae5caf47f6c39fd-poolGrow
 * @id cpp/expat/be4b1c06daba1849b8ff5e00bae5caf47f6c39fd/poolGrow
 * @description expat-be4b1c06daba1849b8ff5e00bae5caf47f6c39fd-expat/lib/xmlparse.c-poolGrow CVE-2016-0718
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vblockSize_6289, LogicalAndExpr target_5, AddExpr target_6, ExprStmt target_7) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vblockSize_6289
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_0.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
		and target_6.getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_7.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation()))
}

predicate func_1(Variable vtemp_6290, LogicalAndExpr target_5, EqualityOperation target_8) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtemp_6290
		and target_1.getExpr().(AssignExpr).getRValue() instanceof VariableCall
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(3)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
		and target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_8.getAnOperand().(VariableAccess).getLocation()))
}

predicate func_2(Variable vblockSize_6304, LogicalAndExpr target_5, RelationalOperation target_9) {
	exists(IfStmt target_2 |
		target_2.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vblockSize_6304
		and target_2.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_2.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(2)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_5
		and target_2.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_9.getLesserOperand().(VariableAccess).getLocation()))
}

predicate func_3(Variable vblockSize_6289, Parameter vpool_6263, VariableCall target_3) {
		target_3.getExpr().(PointerFieldAccess).getTarget().getName()="realloc_fcn"
		and target_3.getExpr().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="mem"
		and target_3.getExpr().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpool_6263
		and target_3.getArgument(0).(PointerFieldAccess).getTarget().getName()="blocks"
		and target_3.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpool_6263
		and target_3.getArgument(1).(AddExpr).getAnOperand().(BuiltInOperationBuiltInOffsetOf).getValue()="12"
		and target_3.getArgument(1).(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vblockSize_6289
		and target_3.getArgument(1).(AddExpr).getAnOperand().(MulExpr).getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_3.getArgument(1).(AddExpr).getAnOperand().(MulExpr).getRightOperand().(SizeofTypeOperator).getValue()="1"
}

predicate func_4(Function func, Initializer target_4) {
		target_4.getExpr() instanceof VariableCall
		and target_4.getExpr().getEnclosingFunction() = func
}

predicate func_5(Parameter vpool_6263, LogicalAndExpr target_5) {
		target_5.getAnOperand().(PointerFieldAccess).getTarget().getName()="blocks"
		and target_5.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpool_6263
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="start"
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpool_6263
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="s"
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="blocks"
		and target_5.getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpool_6263
}

predicate func_6(Variable vblockSize_6289, AddExpr target_6) {
		target_6.getAnOperand().(BuiltInOperationBuiltInOffsetOf).getValue()="12"
		and target_6.getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vblockSize_6289
		and target_6.getAnOperand().(MulExpr).getRightOperand().(SizeofTypeOperator).getType() instanceof LongType
		and target_6.getAnOperand().(MulExpr).getRightOperand().(SizeofTypeOperator).getValue()="1"
}

predicate func_7(Variable vblockSize_6289, Parameter vpool_6263, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="size"
		and target_7.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="blocks"
		and target_7.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpool_6263
		and target_7.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vblockSize_6289
}

predicate func_8(Variable vtemp_6290, EqualityOperation target_8) {
		target_8.getAnOperand().(VariableAccess).getTarget()=vtemp_6290
		and target_8.getAnOperand().(Literal).getValue()="0"
}

predicate func_9(Variable vblockSize_6304, RelationalOperation target_9) {
		 (target_9 instanceof GTExpr or target_9 instanceof LTExpr)
		and target_9.getLesserOperand().(VariableAccess).getTarget()=vblockSize_6304
		and target_9.getGreaterOperand().(Literal).getValue()="1024"
}

from Function func, Variable vblockSize_6289, Variable vtemp_6290, Variable vblockSize_6304, Parameter vpool_6263, VariableCall target_3, Initializer target_4, LogicalAndExpr target_5, AddExpr target_6, ExprStmt target_7, EqualityOperation target_8, RelationalOperation target_9
where
not func_0(vblockSize_6289, target_5, target_6, target_7)
and not func_1(vtemp_6290, target_5, target_8)
and not func_2(vblockSize_6304, target_5, target_9)
and func_3(vblockSize_6289, vpool_6263, target_3)
and func_4(func, target_4)
and func_5(vpool_6263, target_5)
and func_6(vblockSize_6289, target_6)
and func_7(vblockSize_6289, vpool_6263, target_7)
and func_8(vtemp_6290, target_8)
and func_9(vblockSize_6304, target_9)
and vblockSize_6289.getType().hasName("int")
and vtemp_6290.getType().hasName("BLOCK *")
and vblockSize_6304.getType().hasName("int")
and vpool_6263.getType().hasName("STRING_POOL *")
and vblockSize_6289.getParentScope+() = func
and vtemp_6290.getParentScope+() = func
and vblockSize_6304.getParentScope+() = func
and vpool_6263.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
