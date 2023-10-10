/**
 * @name linux-95baa60a0da80a0143e3ddd4d3725758b4513825-ip6_ra_control
 * @id cpp/linux/95baa60a0da80a0143e3ddd4d3725758b4513825/ip6_ra_control
 * @description linux-95baa60a0da80a0143e3ddd4d3725758b4513825-ip6_ra_control 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vnew_ra_64, Parameter vsel_62, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vsel_62
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getTarget()=vnew_ra_64
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-12"
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="12"
		and (func.getEntryPoint().(BlockStmt).getStmt(3)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(3).getFollowingStmt()=target_0))
}

predicate func_1(Variable vnew_ra_64) {
	exists(PointerDereferenceExpr target_1 |
		target_1.getOperand().(VariableAccess).getTarget()=vnew_ra_64)
}

predicate func_2(Parameter vsel_62) {
	exists(RelationalOperation target_2 |
		 (target_2 instanceof GEExpr or target_2 instanceof LEExpr)
		and target_2.getGreaterOperand().(VariableAccess).getTarget()=vsel_62
		and target_2.getLesserOperand().(Literal).getValue()="0")
}

from Function func, Variable vnew_ra_64, Parameter vsel_62
where
not func_0(vnew_ra_64, vsel_62, func)
and vnew_ra_64.getType().hasName("ip6_ra_chain *")
and func_1(vnew_ra_64)
and vsel_62.getType().hasName("int")
and func_2(vsel_62)
and vnew_ra_64.getParentScope+() = func
and vsel_62.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
