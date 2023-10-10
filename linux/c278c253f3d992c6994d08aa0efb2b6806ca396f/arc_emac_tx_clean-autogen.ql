/**
 * @name linux-c278c253f3d992c6994d08aa0efb2b6806ca396f-arc_emac_tx_clean
 * @id cpp/linux/c278c253f3d992c6994d08aa0efb2b6806ca396f/arc_emac_tx_clean
 * @description linux-c278c253f3d992c6994d08aa0efb2b6806ca396f-arc_emac_tx_clean 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vskb_163) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand() instanceof LogicalOrExpr
		and target_0.getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vskb_163
		and target_0.getParent().(IfStmt).getThen().(BreakStmt).toString() = "break;")
}

predicate func_1(Variable vtx_buff_162) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="skb"
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtx_buff_162
		and target_1.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0")
}

predicate func_2(Variable vtxbd_161, Variable vinfo_164) {
	exists(LogicalOrExpr target_2 |
		target_2.getAnOperand().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vinfo_164
		and target_2.getAnOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getValue()="-2147483648"
		and target_2.getAnOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_2.getAnOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="31"
		and target_2.getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="data"
		and target_2.getAnOperand().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtxbd_161
		and target_2.getParent().(IfStmt).getThen().(BreakStmt).toString() = "break;")
}

predicate func_3(Variable vtx_buff_162) {
	exists(PointerFieldAccess target_3 |
		target_3.getTarget().getName()="len"
		and target_3.getQualifier().(VariableAccess).getTarget()=vtx_buff_162)
}

from Function func, Variable vtxbd_161, Variable vtx_buff_162, Variable vskb_163, Variable vinfo_164
where
not func_0(vskb_163)
and not func_1(vtx_buff_162)
and func_2(vtxbd_161, vinfo_164)
and vtxbd_161.getType().hasName("arc_emac_bd *")
and vtx_buff_162.getType().hasName("buffer_state *")
and func_3(vtx_buff_162)
and vskb_163.getType().hasName("sk_buff *")
and vinfo_164.getType().hasName("unsigned int")
and vtxbd_161.getParentScope+() = func
and vtx_buff_162.getParentScope+() = func
and vskb_163.getParentScope+() = func
and vinfo_164.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
