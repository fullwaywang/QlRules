/**
 * @name lcms-91c2db7f2559be504211b283bc3a2c631d6f06d9-cmsAllocProfileSequenceDescription
 * @id cpp/lcms/91c2db7f2559be504211b283bc3a2c631d6f06d9/cmsAllocProfileSequenceDescription
 * @description lcms-91c2db7f2559be504211b283bc3a2c631d6f06d9-src/cmsnamed.c-cmsAllocProfileSequenceDescription CVE-2013-4160
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vSeq_722, Parameter vContextID_720, ExprStmt target_1, ArrayExpr target_2, ExprStmt target_3, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="seq"
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vSeq_722
		and target_0.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("_cmsFree")
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vContextID_720
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vSeq_722
		and target_0.getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(9)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(9).getFollowingStmt()=target_0)
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Variable vSeq_722, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="n"
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vSeq_722
}

predicate func_2(Variable vSeq_722, ArrayExpr target_2) {
		target_2.getArrayBase().(PointerFieldAccess).getTarget().getName()="seq"
		and target_2.getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vSeq_722
}

predicate func_3(Variable vSeq_722, Parameter vContextID_720, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="seq"
		and target_3.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vSeq_722
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("_cmsCalloc")
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vContextID_720
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(SizeofTypeOperator).getType() instanceof LongType
		and target_3.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(SizeofTypeOperator).getValue()="64"
}

from Function func, Variable vSeq_722, Parameter vContextID_720, ExprStmt target_1, ArrayExpr target_2, ExprStmt target_3
where
not func_0(vSeq_722, vContextID_720, target_1, target_2, target_3, func)
and func_1(vSeq_722, target_1)
and func_2(vSeq_722, target_2)
and func_3(vSeq_722, vContextID_720, target_3)
and vSeq_722.getType().hasName("cmsSEQ *")
and vContextID_720.getType().hasName("cmsContext")
and vSeq_722.getParentScope+() = func
and vContextID_720.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
