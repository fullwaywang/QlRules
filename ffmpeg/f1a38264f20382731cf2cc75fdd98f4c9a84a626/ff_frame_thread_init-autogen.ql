/**
 * @name ffmpeg-f1a38264f20382731cf2cc75fdd98f4c9a84a626-ff_frame_thread_init
 * @id cpp/ffmpeg/f1a38264f20382731cf2cc75fdd98f4c9a84a626/ff-frame-thread-init
 * @description ffmpeg-f1a38264f20382731cf2cc75fdd98f4c9a84a626-libavcodec/pthread_frame.c-ff_frame_thread_init CVE-2015-6825
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vcopy_665, NotExpr target_3, ExprStmt target_4) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="priv_data"
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcopy_665
		and target_0.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
		and target_0.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Variable verr_629, NotExpr target_3, ExprStmt target_5) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=verr_629
		and target_1.getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getValue()="-12"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
		and target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation()))
}

predicate func_2(NotExpr target_3, Function func) {
	exists(GotoStmt target_2 |
		target_2.toString() = "goto ..."
		and target_2.getName() ="error"
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
		and target_2.getEnclosingFunction() = func)
}

predicate func_3(Variable vcopy_665, NotExpr target_3) {
		target_3.getOperand().(PointerFieldAccess).getTarget().getName()="internal"
		and target_3.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcopy_665
}

predicate func_4(Variable vcopy_665, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="internal"
		and target_4.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vcopy_665
		and target_4.getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(PointerFieldAccess).getTarget().getName()="internal"
}

predicate func_5(Variable verr_629, ExprStmt target_5) {
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=verr_629
		and target_5.getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getValue()="-12"
}

from Function func, Variable verr_629, Variable vcopy_665, NotExpr target_3, ExprStmt target_4, ExprStmt target_5
where
not func_0(vcopy_665, target_3, target_4)
and not func_1(verr_629, target_3, target_5)
and not func_2(target_3, func)
and func_3(vcopy_665, target_3)
and func_4(vcopy_665, target_4)
and func_5(verr_629, target_5)
and verr_629.getType().hasName("int")
and vcopy_665.getType().hasName("AVCodecContext *")
and verr_629.getParentScope+() = func
and vcopy_665.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
