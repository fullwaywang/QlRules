/**
 * @name linux-99e3a236dd43d06c65af0a2ef9cb44306aef6e02-xdp_umem_reg
 * @id cpp/linux/99e3a236dd43d06c65af0a2ef9cb44306aef6e02/xdp_umem_reg
 * @description linux-99e3a236dd43d06c65af0a2ef9cb44306aef6e02-xdp_umem_reg 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vchunk_size_343, Variable vheadroom_343) {
	exists(RelationalOperation target_0 |
		 (target_0 instanceof GEExpr or target_0 instanceof LEExpr)
		and target_0.getGreaterOperand().(VariableAccess).getTarget()=vheadroom_343
		and target_0.getLesserOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vchunk_size_343
		and target_0.getLesserOperand().(SubExpr).getRightOperand().(Literal).getValue()="256"
		and target_0.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-22"
		and target_0.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="22")
}

predicate func_2(Variable vchunk_size_343, Variable vheadroom_343) {
	exists(SubExpr target_2 |
		target_2.getLeftOperand().(VariableAccess).getTarget()=vchunk_size_343
		and target_2.getRightOperand().(VariableAccess).getTarget()=vheadroom_343)
}

predicate func_4(Variable vsize_chk_346, Function func) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsize_chk_346
		and target_4.getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand() instanceof SubExpr
		and target_4.getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(Literal).getValue()="256"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_4)
}

predicate func_5(Variable vsize_chk_346) {
	exists(RelationalOperation target_5 |
		 (target_5 instanceof GTExpr or target_5 instanceof LTExpr)
		and target_5.getLesserOperand().(VariableAccess).getTarget()=vsize_chk_346
		and target_5.getGreaterOperand().(Literal).getValue()="0"
		and target_5.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-22"
		and target_5.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="22")
}

predicate func_6(Variable vchunks_per_page_344, Variable vchunk_size_343) {
	exists(DivExpr target_6 |
		target_6.getLeftOperand().(BinaryBitwiseOperation).getValue()="4096"
		and target_6.getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_6.getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="12"
		and target_6.getRightOperand().(VariableAccess).getTarget()=vchunk_size_343
		and target_6.getParent().(AssignExpr).getRValue() = target_6
		and target_6.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget()=vchunks_per_page_344)
}

from Function func, Variable vchunks_per_page_344, Variable vsize_chk_346, Variable vchunk_size_343, Variable vheadroom_343
where
not func_0(vchunk_size_343, vheadroom_343)
and func_2(vchunk_size_343, vheadroom_343)
and func_4(vsize_chk_346, func)
and func_5(vsize_chk_346)
and vchunk_size_343.getType().hasName("u32")
and func_6(vchunks_per_page_344, vchunk_size_343)
and vheadroom_343.getType().hasName("u32")
and vchunks_per_page_344.getParentScope+() = func
and vsize_chk_346.getParentScope+() = func
and vchunk_size_343.getParentScope+() = func
and vheadroom_343.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
