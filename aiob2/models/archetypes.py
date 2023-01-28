class B2Object:

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} {' '.join(f'{attr}={value}' for attr, value in self.__dict__.items())}>"
