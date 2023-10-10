/**
 * @name linux-04f25edb48c441fc278ecc154c270f16966cbb90-hclge_shaper_para_calc
 * @id cpp/linux/04f25edb48c441fc278ecc154c270f16966cbb90/hclge_shaper_para_calc
 * @description linux-04f25edb48c441fc278ecc154c270f16966cbb90-hclge_shaper_para_calc 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vir_43) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand() instanceof RelationalOperation
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vir_43
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="100000"
		and target_0.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-22"
		and target_0.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="22")
}

predicate func_1(Parameter vshaper_level_43) {
	exists(RelationalOperation target_1 |
		 (target_1 instanceof GEExpr or target_1 instanceof LEExpr)
		and target_1.getGreaterOperand().(VariableAccess).getTarget()=vshaper_level_43
		and target_1.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-22"
		and target_1.getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="22")
}

from Function func, Parameter vshaper_level_43, Parameter vir_43
where
not func_0(vir_43)
and func_1(vshaper_level_43)
and vshaper_level_43.getType().hasName("u8")
and vir_43.getType().hasName("u32")
and vshaper_level_43.getParentScope+() = func
and vir_43.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
