/**
 * @name freerdp-06c32f170093a6ecde93e3bc07fed6a706bfbeb3-PresentationContext_new
 * @id cpp/freerdp/06c32f170093a6ecde93e3bc07fed6a706bfbeb3/PresentationContext-new
 * @description freerdp-06c32f170093a6ecde93e3bc07fed6a706bfbeb3-channels/video/client/video_main.c-PresentationContext_new CVE-2020-11038
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Function func) {
	exists(AssignExpr target_1 |
		target_1.getLValue().(VariableAccess).getType().hasName("size_t")
		and target_1.getRValue() instanceof MulExpr
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Function func) {
	exists(IfStmt target_2 |
		target_2.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getType().hasName("size_t")
		and target_2.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="2147483647"
		and target_2.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(4)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(4).getFollowingStmt()=target_2))
}

predicate func_3(Variable vret_224, NotExpr target_9, ExprStmt target_10, Function func) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_224
		and target_3.getExpr().(AssignExpr).getRValue() instanceof FunctionCall
		and (func.getEntryPoint().(BlockStmt).getStmt(5)=target_3 or func.getEntryPoint().(BlockStmt).getStmt(5).getFollowingStmt()=target_3)
		and target_9.getOperand().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation())
		and target_3.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_10.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_4(Variable vpriv_223, Variable vret_224, ExprStmt target_11, NotExpr target_12, NotExpr target_13, Function func) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="surfaceData"
		and target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_224
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("BufferPool_Take")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="surfacePool"
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpriv_223
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getType().hasName("size_t")
		and (func.getEntryPoint().(BlockStmt).getStmt(14)=target_4 or func.getEntryPoint().(BlockStmt).getStmt(14).getFollowingStmt()=target_4)
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_11.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_12.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_13.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_6(Function func, FunctionCall target_6) {
		target_6.getTarget().hasName("calloc")
		and target_6.getArgument(0).(Literal).getValue()="1"
		and target_6.getArgument(1).(SizeofExprOperator).getValue()="120"
		and target_6.getEnclosingFunction() = func
}

predicate func_7(Parameter vwidth_221, Parameter vheight_221, Variable vpriv_223, MulExpr target_7) {
		target_7.getLeftOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vwidth_221
		and target_7.getLeftOperand().(MulExpr).getRightOperand().(VariableAccess).getTarget()=vheight_221
		and target_7.getRightOperand().(Literal).getValue()="4"
		and target_7.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("BufferPool_Take")
		and target_7.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="surfacePool"
		and target_7.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpriv_223
}

predicate func_8(Function func, Initializer target_8) {
		target_8.getExpr() instanceof FunctionCall
		and target_8.getExpr().getEnclosingFunction() = func
}

predicate func_9(Variable vret_224, NotExpr target_9) {
		target_9.getOperand().(VariableAccess).getTarget()=vret_224
}

predicate func_10(Variable vret_224, ExprStmt target_10) {
		target_10.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="video"
		and target_10.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_224
}

predicate func_11(Variable vpriv_223, Variable vret_224, ExprStmt target_11) {
		target_11.getExpr().(FunctionCall).getTarget().hasName("BufferPool_Return")
		and target_11.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="surfacePool"
		and target_11.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpriv_223
		and target_11.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="surfaceData"
		and target_11.getExpr().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_224
}

predicate func_12(Variable vret_224, NotExpr target_12) {
		target_12.getOperand().(PointerFieldAccess).getTarget().getName()="currentSample"
		and target_12.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_224
}

predicate func_13(Variable vret_224, NotExpr target_13) {
		target_13.getOperand().(PointerFieldAccess).getTarget().getName()="surfaceData"
		and target_13.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vret_224
}

from Function func, Parameter vwidth_221, Parameter vheight_221, Variable vpriv_223, Variable vret_224, FunctionCall target_6, MulExpr target_7, Initializer target_8, NotExpr target_9, ExprStmt target_10, ExprStmt target_11, NotExpr target_12, NotExpr target_13
where
not func_1(func)
and not func_2(func)
and not func_3(vret_224, target_9, target_10, func)
and not func_4(vpriv_223, vret_224, target_11, target_12, target_13, func)
and func_6(func, target_6)
and func_7(vwidth_221, vheight_221, vpriv_223, target_7)
and func_8(func, target_8)
and func_9(vret_224, target_9)
and func_10(vret_224, target_10)
and func_11(vpriv_223, vret_224, target_11)
and func_12(vret_224, target_12)
and func_13(vret_224, target_13)
and vwidth_221.getType().hasName("UINT32")
and vheight_221.getType().hasName("UINT32")
and vpriv_223.getType().hasName("VideoClientContextPriv *")
and vret_224.getType().hasName("PresentationContext *")
and vwidth_221.getParentScope+() = func
and vheight_221.getParentScope+() = func
and vpriv_223.getParentScope+() = func
and vret_224.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
