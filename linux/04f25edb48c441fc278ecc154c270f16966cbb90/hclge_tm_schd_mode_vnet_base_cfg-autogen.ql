/**
 * @name linux-04f25edb48c441fc278ecc154c270f16966cbb90-hclge_tm_schd_mode_vnet_base_cfg
 * @id cpp/linux/04f25edb48c441fc278ecc154c270f16966cbb90/hclge_tm_schd_mode_vnet_base_cfg
 * @description linux-04f25edb48c441fc278ecc154c270f16966cbb90-hclge_tm_schd_mode_vnet_base_cfg 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vvport_1134, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="vport_id"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvport_1134
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="8"
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-22"
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="22"
		and (func.getEntryPoint().(BlockStmt).getStmt(4)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(4).getFollowingStmt()=target_0))
}

predicate func_1(Parameter vvport_1134) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="back"
		and target_1.getQualifier().(VariableAccess).getTarget()=vvport_1134)
}

from Function func, Parameter vvport_1134
where
not func_0(vvport_1134, func)
and vvport_1134.getType().hasName("hclge_vport *")
and func_1(vvport_1134)
and vvport_1134.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
