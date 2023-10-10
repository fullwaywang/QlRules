/**
 * @name linux-66d42ed8b25b64eb63111a2b8582c5afc8bf1105-ppp_cp_parse_cr
 * @id cpp/linux/66d42ed8b25b64eb63111a2b8582c5afc8bf1105/ppp_cp_parse_cr
 * @description linux-66d42ed8b25b64eb63111a2b8582c5afc8bf1105-ppp_cp_parse_cr 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_2(Variable vvalid_accm_375, Variable vopt_376) {
	exists(IfStmt target_2 |
		target_2.getCondition().(RelationalOperation).getLesserOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vopt_376
		and target_2.getCondition().(RelationalOperation).getLesserOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_2.getCondition().(RelationalOperation).getGreaterOperand().(SizeofExprOperator).getValue()="6"
		and target_2.getCondition().(RelationalOperation).getGreaterOperand().(SizeofExprOperator).getExprOperand().(VariableAccess).getTarget()=vvalid_accm_375
		and target_2.getThen().(GotoStmt).toString() = "goto ...")
}

predicate func_3(Variable vlen_378) {
	exists(IfStmt target_3 |
		target_3.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vlen_378
		and target_3.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="6"
		and target_3.getThen().(GotoStmt).toString() = "goto ...")
}

predicate func_4(Function func) {
	exists(LabelStmt target_4 |
		target_4.toString() = "label ...:"
		and (func.getEntryPoint().(BlockStmt).getStmt(9)=target_4 or func.getEntryPoint().(BlockStmt).getStmt(9).getFollowingStmt()=target_4))
}

predicate func_10(Variable vopt_376) {
	exists(ArrayExpr target_10 |
		target_10.getArrayBase().(VariableAccess).getTarget()=vopt_376
		and target_10.getArrayOffset().(Literal).getValue()="1")
}

predicate func_11(Variable vopt_376) {
	exists(ArrayExpr target_11 |
		target_11.getArrayBase().(VariableAccess).getTarget()=vopt_376
		and target_11.getArrayOffset().(Literal).getValue()="0")
}

predicate func_12(Variable vopt_376, Variable vlen_378) {
	exists(RelationalOperation target_12 |
		 (target_12 instanceof GTExpr or target_12 instanceof LTExpr)
		and target_12.getLesserOperand().(VariableAccess).getTarget()=vlen_378
		and target_12.getGreaterOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vopt_376
		and target_12.getGreaterOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_12.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(0) instanceof ExprStmt
		and target_12.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1) instanceof ExprStmt
		and target_12.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2) instanceof ReturnStmt)
}

from Function func, Parameter vdev_372, Parameter vpid_372, Variable vvalid_accm_375, Variable vopt_376, Variable vout_377, Variable vlen_378
where
not func_2(vvalid_accm_375, vopt_376)
and not func_3(vlen_378)
and not func_4(func)
and vdev_372.getType().hasName("net_device *")
and vpid_372.getType().hasName("u16")
and vvalid_accm_375.getType().hasName("const u8[6]")
and vopt_376.getType().hasName("const u8 *")
and func_10(vopt_376)
and func_11(vopt_376)
and vout_377.getType().hasName("u8 *")
and vlen_378.getType().hasName("unsigned int")
and func_12(vopt_376, vlen_378)
and vdev_372.getParentScope+() = func
and vpid_372.getParentScope+() = func
and vvalid_accm_375.getParentScope+() = func
and vopt_376.getParentScope+() = func
and vout_377.getParentScope+() = func
and vlen_378.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
