/**
 * @name imagemagick-716496e6df0add89e9679d6da9c0afca814cfe49-ReadTIM2Image
 * @id cpp/imagemagick/716496e6df0add89e9679d6da9c0afca814cfe49/ReadTIM2Image
 * @description imagemagick-716496e6df0add89e9679d6da9c0afca814cfe49-coders/tim2.c-ReadTIM2Image CVE-2022-2719
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Variable vi_688) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vi_688
		and target_1.getExpr().(AssignExpr).getRValue() instanceof Literal)
}

predicate func_2(Variable vi_688, RelationalOperation target_6) {
	exists(PostfixIncrExpr target_2 |
		target_2.getOperand().(VariableAccess).getTarget()=vi_688
		and target_2.getOperand().(VariableAccess).getLocation().isBefore(target_6.getLesserOperand().(VariableAccess).getLocation()))
}

predicate func_5(Variable vi_688, PrefixIncrExpr target_5) {
		target_5.getOperand().(VariableAccess).getTarget()=vi_688
}

predicate func_6(Variable vi_688, RelationalOperation target_6) {
		 (target_6 instanceof GTExpr or target_6 instanceof LTExpr)
		and target_6.getLesserOperand().(VariableAccess).getTarget()=vi_688
		and target_6.getGreaterOperand().(ValueFieldAccess).getTarget().getName()="image_count"
}

from Function func, Variable vi_688, PrefixIncrExpr target_5, RelationalOperation target_6
where
not func_1(vi_688)
and not func_2(vi_688, target_6)
and func_5(vi_688, target_5)
and func_6(vi_688, target_6)
and vi_688.getType().hasName("int")
and vi_688.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
