/**
 * @name linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-mt7921_init_wiphy
 * @id cpp/linux/28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1/mt7921-init-wiphy
 * @description linux-28131d896d6d316bc1f6f305d1a9ed6d96c3f2a1-mt7921_init_wiphy CVE-2020-24588
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(ComplementExpr target_0 |
		target_0.getValue()="4294967039"
		and target_0.getOperand() instanceof EnumConstantAccess
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(BitwiseOrExpr target_1 |
		target_1.getValue()="352"
		and target_1.getLeftOperand().(BitwiseOrExpr).getValue()="288"
		and target_1.getLeftOperand().(BitwiseOrExpr).getLeftOperand() instanceof EnumConstantAccess
		and target_1.getEnclosingFunction() = func)
}

from Function func
where
func_0(func)
and not func_1(func)
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
